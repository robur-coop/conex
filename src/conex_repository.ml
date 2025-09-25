open Conex_resource
open Conex_utils

type t = {
  root : Root.t ;
  targets : (Digest.t * Uint.t * S.t) Tree.t ;
}

let root t = t.root

let keydir t = t.root.Root.keydir

let datadir t = t.root.Root.datadir

let maintainer_delegation t =
  match Root.RM.find_opt `Maintainer t.root.Root.roles with
  | None -> None
  | Some e -> Some (e, false, S.singleton "root")

let timestamp t =
  Option.fold
    ~none:(Ok None)
    ~some:(function
        | Expression.Quorum (1, ks) when Expression.KS.cardinal ks = 1 ->
          (* assume a single timestamp *)
          begin match Expression.KS.choose ks with
            | Local _ ->
              Error "only a single remote key expression allowed for timestamp"
            | Remote (id, dgst, epoch) -> Ok (Some (id, dgst, epoch))
          end
        | _ ->
          Error "only a single key expression with quorum 1 allowed for timestamp")
    (Root.RM.find_opt `Timestamp (root t).Root.roles)

let snapshot t =
  Option.fold
    ~none:(Ok None)
    ~some:(function
        | Expression.Quorum (1, ks) when Expression.KS.cardinal ks = 1 ->
          (* assume a single snapshot *)
          begin match Expression.KS.choose ks with
            | Local _ ->
              Error "only a single remote key expression allowed for snapshot"
            | Remote (id, dgst, epoch) -> Ok (Some (id, dgst, epoch))
          end
        | _ ->
          Error "only a single key expression with quorum 1 allowed for snapshot")
    (Root.RM.find_opt `Snapshot (root t).Root.roles)

let targets t = t.targets

let with_targets t targets = { t with targets }

let create root =
  let targets = Tree.empty in
  { root ; targets }

type res = [
  | `Only_on_disk of path
  | `Only_in_targets of path
  | `No_match of path * (Digest.t * Uint.t) list * (Digest.t * Uint.t * S.t) list
]

let pp_res ppf =
  let pp_d ppf (dgst, len) =
    Format.fprintf ppf "%s bytes, %a" (Uint.decimal len) Digest.pp dgst
  and pp_t ppf (dgst, len, _) =
    Format.fprintf ppf "%s bytes, %a" (Uint.decimal len) Digest.pp dgst
  in
  function
  | `Only_on_disk p -> Format.fprintf ppf "path %a only exists on disk" pp_path p
  | `Only_in_targets p -> Format.fprintf ppf "path %a only exists in targets" pp_path p
  | `No_match (p, disk, targets) ->
    Format.fprintf ppf "no matching digest for %a (on_disk %a, targets %a)"
      pp_path p (pp_list pp_d) disk (pp_list pp_t) targets
[@@coverage off]

let validate_targets t on_disk =
  (* foreach digest in on_disk there exists a matching one in t.targets
     if there is no such digest -> `Only_on_disk
     if the digest does not match -> `No_match
     then, fold over t.targets, validate there exists a matching one in on_disk
     if there is no such digest -> `Only_in_targets
     if there is such a digest, it must match (see check above)
 *)
  let on_d =
    let matches (dgst, len) (dgst', len', _) =
      Digest.equal dgst dgst' && Uint.compare len len' = 0
    in
    Tree.fold (fun path ds acc ->
        match ds with
        | [] -> acc
        | _ -> match Tree.lookup path t.targets with
          | None ->
            if Target.collect_opam_file
                t.root.Root.datadir
                Target.{ filename = path ; digest = []; size = Uint.zero }
            then
              `Only_on_disk path :: acc
            else
              acc
          | Some xs ->
            let in_targets d = List.exists (matches d) xs in
            if List.exists in_targets ds
            then acc
            else `No_match (path, ds, xs) :: acc)
      [] on_disk
  in
  Tree.fold (fun path xs acc ->
      match xs with
      | [] -> acc
      | _ -> match Tree.lookup path on_disk with
        | None -> `Only_in_targets path :: acc
        | Some _ -> acc)
    on_d t.targets

let fold_targets f acc id_d targets =
(*  M.iter (fun id (dgst, epoch) ->
      Printf.printf "[fold_targets] id %s digest %s epoch %s\n"
        id (Digest.to_string dgst) (Uint.decimal epoch))
    id_d ; *)
  List.fold_left (fun acc target ->
      match M.find_opt target.Targets.name id_d with
      | None ->
        Format.printf "couldn't find id %a in id_d@." pp_id target.Targets.name ;
        acc
      | Some (dgst, epoch) -> f acc dgst epoch target)
    acc targets

module Expr_map = struct
  include Map.Make(Expression)
end

let collect_and_validate_delegations id_d parent expr targets =
  let tree =
    fold_targets (fun tree dgst epoch target ->
        List.fold_left (fun tree delegation ->
            (* Format.printf "inserting delegation %a (origin %a)@."
               Delegation.pp delegation pp_id target.Targets.name ; *)
            List.fold_left (fun tree path ->
                if subpath ~parent path then begin
                  Tree.insert path
                    (delegation.Delegation.terminating,
                     delegation.Delegation.valid,
                     target.Targets.name, dgst, epoch)
                    tree
                  end else begin
                    Format.printf "WARN ignoring delegation %a (path %a is not below parent %a)@."
                      Delegation.pp delegation
                      pp_path path pp_path parent ;
                    tree
                  end)
                tree delegation.Delegation.paths)
            tree target.Targets.delegations)
      Tree.empty id_d targets
  in
  (* now, tree contains at its nodes a list of
     (bool * Expression.t * identifier * Digest.t * Uint.t) *)
  let good_ones =
    Tree.fold (fun path stuff acc ->
        let em =
          List.fold_left (fun acc (terminating, expression, id, keyid, epoch) ->
              let supporter = (terminating, id, keyid, epoch) in
              (* Format.printf "inserting expr %a (terminating %b) (supporter %a) for %a@."
                 Expression.pp expression terminating pp_id id pp_path path ; *)
              let v = match Expr_map.find_opt expression acc with
                | None -> [ supporter ]
                | Some m -> supporter :: m
              in
              Expr_map.add expression v acc)
            Expr_map.empty stuff
        in
        Expr_map.fold (fun expression ss acc ->
            (* eval expression foreach thing *)
            let t, nont = List.partition (fun (t, _, _, _) -> t) ss in
            (* Format.printf "expr %a path %a %d terminating, %d non-terminating@."
               Expression.pp expression pp_path path (List.length t) (List.length nont) ; *)
            let dms xs =
              List.fold_left (fun (dm, s) (_, id, keyid, epoch) ->
                  (* Format.printf "adding %a for %a@." pp_id id pp_path path ; *)
                  Digest_map.add keyid (id, epoch) dm, S.add id s)
                (Digest_map.empty, S.empty) xs
            in
            let ts, tss = dms t
            and nonts, nontss = dms nont
            in
            (* Format.printf "evaluating expr %a for %a and %a@."
              Expression.pp expr pp_path path Expression.pp expression ; *)
            if Expression.eval expr ts S.empty then
              (path, expression, true, tss) :: acc
            else if Expression.eval expr nonts S.empty then
              (path, expression, false, nontss) :: acc
            else begin
              Format.printf "expression %a couldn't evaluate for %a@."
                Expression.pp expression pp_path path ;
              acc
            end) em acc)
      [] tree
  in
(*  let pp_t ppf (path, expr, t, s) =
    Format.fprintf ppf "path %a expr %a terminating %b supporters %a@."
      pp_path path Expression.pp expr t S.pp s
  in
    Format.printf "at the end, our delegations %a@." (pp_list pp_t) good_ones ; *)
  (* each checksum that is good in that setting is allowed to return from here,
     and being inserted into a global tree of valid checksums *)
  good_ones

let collect_and_validate_targets ?(tree = Tree.empty) id_d parent expr targets =
  let ttree =
    fold_targets (fun tree dgst epoch target ->
        List.fold_left (fun tree chk ->
            if subpath ~parent chk.Target.filename then begin
(*              Format.printf "inserting target %a (origin %a)@."
                Target.pp chk pp_id target.Targets.name ; *)
              Tree.insert chk.Target.filename
                (chk.Target.digest, chk.Target.size,
                 target.Targets.name, dgst, epoch)
                tree
            end else begin
              Format.printf "WARN ignoring target %a (path %a is not below parent %a@."
                Target.pp chk pp_path chk.Target.filename pp_path parent ;
              tree
            end)
          tree target.Targets.targets)
      Tree.empty id_d targets
  in
  (* once that is in there, fold over tree and eval expr with the stored "digest maps" *)
  let good_ones =
    Tree.fold (fun path stuff acc ->
        (* need to go over the stuff list and sort by first projection: *)
        (* this is a digest list -- now we need to put all the digests somewhere *)
        (* and get the key_dgst, name, epoch as DigestMap on the RHS, *)
        let dm =
          List.fold_left (fun acc (chks, len, id, keyid, epoch) ->
              let supporter = (id, keyid, epoch) in
              List.fold_left (fun acc dgst ->
(*                  Format.printf "inserting digest %a (supporter %a) for %a (digest %a, len %s)@."
                    Digest.pp dgst pp_id id pp_path path Digest.pp dgst (Uint.decimal len) ; *)
                  let v = match Digest_map.find_opt dgst acc with
                    | None -> Uint_map.add len [ supporter ] Uint_map.empty
                    | Some m ->
                      match Uint_map.find_opt len m with
                      | None -> Uint_map.add len [ supporter ] m
                      | Some sups -> Uint_map.add len (supporter :: sups) m
                  in
                  Digest_map.add dgst v acc) acc chks)
            Digest_map.empty stuff
        in
        Digest_map.fold (fun dgst m tree ->
            (* eval expression foreach thing *)
            Uint_map.fold (fun len sups tree ->
                let dm, s =
                  List.fold_left (fun (dm, s) (id, keyid, epoch) ->
                      (* Format.printf "adding %a for %a (digest %a, len %s)@."
                         pp_id id pp_path path Digest.pp dgst (Uint.decimal len) ; *)
                      Digest_map.add keyid (id, epoch) dm, S.add id s)
                    (Digest_map.empty, S.empty) sups
                in
                (* Format.printf "evaluating expr %a for %a (digest %a, len %s)@."
                   Expression.pp expr pp_path path Digest.pp dgst (Uint.decimal len) ; *)
                if Expression.eval expr dm S.empty then
                  Tree.insert path (dgst, len, s) tree
                else begin
                  Format.printf "expression %a couldn't evaluate for %a (digest %a, len %s)@."
                    Expression.pp expr pp_path path Digest.pp dgst (Uint.decimal len) ;
                  tree
                end) m tree)
          dm acc)
      tree ttree
  in
  (*
  let pp_t ppf (dgst, len, s) =
    Format.fprintf ppf "digest %a len %s supporters %a@."
      Digest.pp dgst (Uint.decimal len) S.pp s
  in
  Format.printf "at the end, our tree %a@." (Tree.pp pp_t) good_ones ; *)
  (* each checksum that is good in that setting is allowed to return from here,
     and being inserted into a global tree of valid checksums *)
  good_ones
