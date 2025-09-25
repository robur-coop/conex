open Conex_utils
open Conex_resource

let ( let* ) = Result.bind

module Make (L : LOGS) (C : Conex_verify.S) = struct

  module IO = Conex_io.Make(L)

  let valid_ids valid sigs =
    Digest_map.fold (fun dgst id acc ->
        if valid dgst id
        then S.add id acc
        else begin
          L.info (fun m -> m "%a (%a) is not a valid root key"
                     pp_id id Digest.pp dgst) ;
          acc
        end)
      sigs S.empty

  let verify_root ?(valid = fun _ _ -> false) ?quorum io filename =
    L.debug (fun m -> m "verifying root: %a" pp_name filename) ;
    let* root, warn = err_to_str Conex_io.pp_r_err (IO.read_root io filename) in
    List.iter (fun msg -> L.warn (fun m -> m "%s" msg)) warn ;
    (* verify signatures *)
    let sigs, errs =
      C.verify (Root.wire_raw root) root.Root.keys root.Root.signatures
    in
    List.iter (fun e -> L.warn (fun m -> m "%a" Conex_verify.pp_error e)) errs ;
    (* need to unique over keyids *)
    let ids = valid_ids valid sigs in
    let quorum_satisfied =
      Option.fold ~none:true ~some:(fun q -> q <= S.cardinal ids) quorum
    in
    match
      Expression.eval root.Root.valid Digest_map.empty ids,
      quorum_satisfied
    with
    | true, true -> Ok (Conex_repository.create root)
    | false, _ -> Error "couldn't validate root role"
    | _, false -> Error "provided quorum was not matched"

  let verify_timestamp ?id io repo ~timestamp_expiry ~now =
    L.debug (fun m -> m "verifying timestamp") ;
    let* r = Conex_repository.timestamp repo in
    let read_and_verify id =
      let* ts, warn = err_to_str Conex_io.pp_r_err (IO.read_timestamp io id) in
      List.iter (fun w -> L.warn (fun m -> m "%s" w)) warn ;
      let sigs, es =
        Timestamp.(C.verify (wire_raw ts) ts.keys ts.signatures)
      in
      List.iter (fun e -> L.warn (fun m -> m "%a" Conex_verify.pp_error e)) es ;
      Ok (ts, sigs)
    in
    let validate_with_root (id, dgst, epoch) ts sigs =
      match Digest_map.find_opt dgst sigs with
      | None -> Error "couldn't validate timestamp signature"
      | Some id' ->
        match id_equal id id', Uint.compare epoch ts.Timestamp.epoch = 0 with
        | false, _ ->
          L.warn (fun m -> m "delegated public key was not used for signature on timestamp");
          Error "no valid signature on timestamp"
        | true, false ->
          L.warn (fun m -> m "timestamp epoch mismatch: root %a, timestamp %a"
                     Uint.pp epoch Uint.pp ts.Timestamp.epoch);
          Error "timestamp with bad epoch"
        | true, true ->
          begin match
              timestamp_to_int64 ts.Timestamp.created,
              timestamp_to_int64 now
            with
            | Ok ts_sec, Ok now_sec ->
              if ts_sec > now_sec then
                L.warn (fun m -> m "timestamp is in the future (%s, now %s)"
                           ts.Timestamp.created now);
              if ts_sec <= Int64.add now_sec timestamp_expiry then
                Ok (Some ts)
              else
                (L.warn (fun m -> m "timestamp is invalid (%s, now %s)"
                            ts.Timestamp.created now);
                 Error "timestamp is no longer valid")
            | Error _ as e, _ | _, (Error _ as e) ->
              L.warn (fun m -> m "error converting some timestamp %s or %s"
                         ts.Timestamp.created now);
              e
          end
    in
    match r, id with
    | None, None ->
      L.warn (fun m -> m "no timestamp role found in root, and no ID provided") ;
      Ok None
    | Some (id, _, _), Some id' when not (id_equal id id') ->
      L.warn (fun m -> m "ID mismatch: timestamp in root %a, provided %a, \
                          using %a and not validating against root"
                 pp_id id pp_id id' pp_id id') ;
      let* ts, _ = read_and_verify id' in
      Ok (Some ts)
    | Some (id, dgst, epoch), _ ->
      let* ts, sigs = read_and_verify id in
      validate_with_root (id, dgst, epoch) ts sigs
    | None, Some id ->
      L.warn (fun m -> m "no timestamp role found in root") ;
      let* ts, _ = read_and_verify id in
      Ok (Some ts)

  let verify_snapshot ?timestamp ?id io repo =
    L.debug (fun m -> m "verifying timestamp") ;
    let* r = Conex_repository.snapshot repo in
    let read_and_verify id =
      let* snap, warn = err_to_str Conex_io.pp_r_err (IO.read_snapshot io id) in
      List.iter (fun w -> L.warn (fun m -> m "%s" w)) warn ;
      let sigs, es =
        Snapshot.(C.verify (wire_raw snap) snap.keys snap.signatures)
      in
      List.iter (fun e -> L.warn (fun m -> m "%a" Conex_verify.pp_error e)) es ;
      Ok (snap, sigs)
    in
    let validate_with_root (id, dgst, epoch) snap sigs =
      match Digest_map.find_opt dgst sigs with
      | None -> Error "couldn't validate snapshot signature"
      | Some id' ->
        match id_equal id id', Uint.compare epoch snap.Snapshot.epoch = 0 with
        | false, _ ->
          L.warn (fun m -> m "delegated public key was not used for signature on snapshot");
          Error "no valid signature on snapshot"
        | true, false ->
          L.warn (fun m -> m "snapshot epoch mismatch: root %a, snapshot %a"
                     Uint.pp epoch Uint.pp snap.Snapshot.epoch);
          Error "snapshot with bad epoch"
        | true, true ->
          begin match timestamp with
            | None ->
              L.warn (fun m -> m "no timestamp provided, taking snapshot as is");
              Ok (Some snap)
            | Some ts ->
              let* tgt =
                let snap_path = Conex_repository.keydir repo @ [ id ] in
                IO.compute_checksum_file io C.raw_digest snap_path
              in
              if List.exists (Target.equal tgt) ts.Timestamp.targets then
                Ok (Some snap)
              else
                Error "couldn't validate snapshot: no match in timestamp target"
          end
    in
    match r, id with
    | None, None ->
      L.warn (fun m -> m "no snapshot role found in root and none provided") ;
      Ok None
    | Some (id, _, _), Some id' when not (id_equal id id') ->
      L.warn (fun m -> m "ID mismatch: snapshot in root %a, provided %a, \
                          using %a and not validating against root"
                 pp_id id pp_id id' pp_id id') ;
      let* snap, _ = read_and_verify id' in
      Ok (Some snap)
    | Some (id, dgst, epoch), _ ->
      let* snap, sigs = read_and_verify id in
      validate_with_root (id, dgst, epoch) snap sigs
    | None, Some id ->
      L.warn (fun m -> m "no snapshot role found in root") ;
      let* snap, _ = read_and_verify id in
      Ok (Some snap)

  let targets_cache = ref M.empty

  let verify_targets ?snapshot io repo opam id =
    L.debug (fun m -> m "verifying target %a" pp_id id) ;
    match M.find_opt id !targets_cache with
    | Some targets ->
      L.debug (fun m -> m "found in cache") ;
      Ok targets
    | None ->
      let root = Conex_repository.root repo in
      let* targets, warn =
        err_to_str Conex_io.pp_r_err (IO.read_targets io root opam id)
      in
      List.iter (fun msg -> L.warn (fun m -> m "%s" msg)) warn ;
      let* () = match snapshot with
        | None -> Ok ()
        | Some snap ->
          let path = Conex_repository.keydir repo @ [ id ] in
          let* tgt = IO.compute_checksum_file io C.raw_digest path in
          if List.exists (Target.equal tgt) snap.Snapshot.targets then
            Ok ()
          else
            let msg =
              "couldn't validate target " ^ id ^ ": no match in snapshot targets"
            in
            Error msg
      in
      let sigs, es =
        Targets.(C.verify (wire_raw targets) targets.keys targets.signatures)
      in
      List.iter (fun e -> L.warn (fun m -> m "%a" Conex_verify.pp_error e)) es ;
      let s = Digest_map.fold (fun _ id acc -> S.add id acc) sigs S.empty in
      (* assumes that expression is valid using only target-local (keys and) signatures! *)
      if Expression.eval targets.Targets.valid Digest_map.empty s then begin
        targets_cache := M.add id targets !targets_cache ;
        Ok targets
      end else
        Error ("couldn't validate expression in targets " ^ id)

  let compare_with_disk ignore_missing io repo =
    let non_strict_res = function
      | `Only_on_disk p ->
        (* we have sth like foo/foo.0/<file>, and check that targets doesn't
           have anything in foo/  *)
        begin match p with
          | [] -> L.warn (fun m -> m "shouldn't happen, empty path") ; false (* unclear, should not happen *)
          | pkg::_ -> not (Tree.(is_empty (sub [pkg] (Conex_repository.targets repo))))
        end
      | _ -> true
    in
    let* on_disk = IO.compute_checksum_tree ~prefix:(Conex_repository.root repo).Root.datadir io C.raw_digest in
    let errs = Conex_repository.validate_targets repo on_disk in
    List.iter (fun r ->
        L.warn (fun m -> m "%a" Conex_repository.pp_res r))
      errs ;
    match ignore_missing, errs with
    | _, [] -> Ok ()
    | false, _ -> Error "comparison failed"
    | true, _ -> match List.filter non_strict_res errs with
      | [] -> Ok ()
      | _ -> Error "non-strict comparison failed"

  let collect_targets ?snapshot io repo opam keyrefs =
    M.fold (fun id (dgst, epoch) (dm, id_d, targets) ->
        match verify_targets ?snapshot io repo opam id with
        | Error msg ->
          L.warn (fun m -> m "couldn't load or verify target %a: %s" pp_id id msg) ;
          (dm, id_d, targets)
        | Ok target ->
          let keys =
            M.fold (fun id key m -> M.add id (Key.to_string key) m)
              target.Targets.keys M.empty
          in
          match Expression.hash C.raw_digest keys target.Targets.valid with
          | Error e ->
            L.warn (fun m -> m "%s" e) ;
            (dm, id_d, targets)
          | Ok valid_h ->
            if
              Uint.compare target.Targets.epoch epoch = 0 &&
              Digest.equal valid_h dgst
            then
              (* now we add as _id_ (of our keyref) the epoch and dgst to dm *)
              let id_d' = M.add id (dgst, epoch) id_d in
              (Digest_map.add dgst (id, epoch) dm, id_d', target :: targets)
            else begin
              L.warn (fun m -> m "dropping %a since epoch (%a vs %a) or digest mismatch"
                         pp_id id Uint.pp epoch Uint.pp target.Targets.epoch) ;
              (dm, id_d, targets)
            end)
      keyrefs (Digest_map.empty, M.empty, [])

  let verify_one ?snapshot io repo opam path expr terminating =
    let keyrefs = Expression.keys M.empty expr in
    let dm, id_d, targets = collect_targets ?snapshot io repo opam keyrefs in
    if Expression.eval expr dm S.empty then begin
      let tree = Conex_repository.targets repo in
      let tree' = Conex_repository.collect_and_validate_targets ~tree id_d path expr targets in
      let repo' = Conex_repository.with_targets repo tree' in
      let delegations =
        if terminating then begin
          L.debug (fun m -> m "terminating delegation, not inspecting further") ;
          []
        end else
          Conex_repository.collect_and_validate_delegations id_d path expr targets
      in
      (repo', delegations)
    end else begin
      let pp_id_ep ppf (id, epoch) = Format.fprintf ppf "%a (#%s)" pp_id id (Uint.to_string epoch) in
      L.warn (fun m -> m "expression %a does not eval to true with %a"
                 Expression.pp expr (Digest_map.pp pp_id_ep) dm) ;
      (repo, [])
    end

  let verify ?(ignore_missing = false) ?snapshot io repo opam =
    let* expr, term, supp =
      Option.to_result ~none:"no delegation for maintainers"
        (Conex_repository.maintainer_delegation repo)
    in
    (* queue is mutable, not thread safe, raises on pop when empty
       - it does not leave the scope here
       - pop is guarded by the is_empty *)
    let q = Queue.create () in
    (* termination argument is tricky here, but:
       - delegations may delegate (unless terminating = true) any subpath
         (subpath ~parent:p p is false forall p!)
       - maybe path should be limited in length (2?3?)
    *)
    (* TODO: if snapshot is provided, ensure all targets of snap are present (!?) *)
    let rec process_delegation repo =
      if Queue.is_empty q
      then repo
      else begin
        let (path, expr, terminating, _supp) = Queue.pop q in
        let repo', dels = verify_one ?snapshot io repo opam path expr terminating in
        List.iter (fun (p, e, t, s) ->
            L.debug (fun m -> m "pushing delegation path %a expr %a terminating %b s %a"
                        pp_path p Expression.pp e t S.pp s) ;
            Queue.push (p, e, t, s) q)
          dels ;
        process_delegation repo'
      end
    in
    Queue.push (root, expr, term, supp) q ;
    let repo' = process_delegation repo in
    let pp_t ppf (dgst, len, s) =
      Format.fprintf ppf "digest %a len %s supporters %a@."
        Digest.pp dgst (Uint.decimal len) S.pp s
    in
    L.debug (fun m -> m "end of verification, targets tree is %a"
                (Tree.pp pp_t) (Conex_repository.targets repo')) ;
    compare_with_disk ignore_missing io repo'

  let verify_diffs root io newio diffs opam =
    let* old_root, warn = err_to_str Conex_io.pp_r_err (IO.read_root io root) in
    List.iter (fun msg -> L.warn (fun m -> m "%s" msg)) warn ;
    let* new_root, warn' = err_to_str Conex_io.pp_r_err (IO.read_root newio root) in
    List.iter (fun msg -> L.warn (fun m -> m "%s" msg)) warn' ;
    let* () =
      guard (path_equal old_root.Root.keydir new_root.Root.keydir)
        "old and new key directories are differrent"
    in
    let* r, ids = Conex_diff.ids root new_root.Root.keydir diffs in
    L.debug (fun m -> m "root is modified? %b, ids %a" r S.pp ids) ;
    let* () =
      match Uint.compare old_root.Root.counter new_root.Root.counter with
      | 0 when r -> Error "root counter same, expected to increase"
      | 0 (* when not r *) -> Ok ()
      | x when x > 0 -> Error "root counter decremented"
      | _ (* when x < 0 *) -> Ok ()
    in
    S.fold (fun id acc ->
        let* () = acc in
        match IO.read_targets io old_root opam id, IO.read_targets newio new_root opam id with
        | Error _, Ok _ -> Ok ()
        | Error _, Error e -> err_to_str Conex_io.pp_r_err (Error e)
        | Ok _, Error e -> err_to_str Conex_io.pp_r_err (Error e) (* TODO allow delete? *)
        | Ok (t, _), Ok (t', _) ->
          match
            Uint.compare t.Targets.epoch t'.Targets.epoch,
            Uint.compare t.Targets.counter t'.Targets.counter
          with
          | 0, 0 -> Error ("counter and epoch of " ^ id ^ " same")
          | 0, y when y > 0 -> Error ("counter of " ^ id ^ " is moving backwards")
          | 0, _ (* when y < 0 *) -> Ok ()
          | x, _ when x < 0 -> Ok ()
          | _, _ (* when x > 0 *) -> Error ("epoch of " ^ id ^ " is moving backwards"))
      ids (Ok ())
end
