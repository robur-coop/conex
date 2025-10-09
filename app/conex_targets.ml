open Conex_utils
open Conex_resource

open Conex_opts
open Conex_mc

module IO = Conex_io.Make(Logs)

let ( let* ) = Result.bind

let find_id io root id =
  let id = Option.value ~default:"" id in
  match List.filter (fun x -> String.is_prefix ~prefix:id x) (IO.targets io root) with
  | [ x ] -> Ok x
  | [] -> Error "no id found with given prefix"
  | _ -> Error "multiple ids found with given prefix"

let status _ repodir id root_file no_opam =
  msg_to_cmdliner (
    let* io = repo ~rw:false repodir in
    let* root, warn = to_str Conex_io.pp_r_err (IO.read_root io root_file) in
    List.iter (fun msg -> Logs.warn (fun m -> m "%s" msg)) warn ;
    Logs.debug (fun m -> m "root file %a" Root.pp root) ;
    let repo = Conex_repository.create root in
    let* id' = find_id io root id in
    let* targets = C.verify_targets io repo (not no_opam) id' in
    Logs.app (fun m -> m "targets file %a" Targets.pp targets) ;
    Ok ())

let create _ repodir id dry root_file no_opam =
  (* given private key id, create an initial targets template! *)
  msg_to_cmdliner (
    let* priv, id' = init_priv_id id in
    let* io = repo ~rw:(not dry) repodir in
    let* root, warn = to_str Conex_io.pp_r_err (IO.read_root io root_file) in
    List.iter (fun msg -> Logs.warn (fun m -> m "%s" msg)) warn ;
    Logs.debug (fun m -> m "root file %a" Root.pp root) ;
    let targets =
      Result.fold
        ~error:(fun _ ->
            let pub = PRIV.pub_of_priv priv in
            let keyref = Expression.Local id' in
            let keys = M.add id' pub M.empty in
            let valid = Expression.(Quorum (1, KS.singleton keyref)) in
            Targets.t ~keys now id' valid)
        ~ok:(fun (targets, warn) ->
            List.iter (fun msg -> Logs.warn (fun m -> m "%s" msg)) warn ;
            targets)
        (IO.read_targets io root (not no_opam) id')
    in
    Logs.app (fun m -> m "targets file %a" Targets.pp targets) ;
    IO.write_targets io root targets)

let hash _ repodir id root_file no_opam =
  msg_to_cmdliner (
    let* id' = Option.to_result ~none:"requires id" id in
    let* io = repo ~rw:false repodir in
    let* root, warn = to_str Conex_io.pp_r_err (IO.read_root io root_file) in
    List.iter (fun msg -> Logs.warn (fun m -> m "%s" msg)) warn ;
    Logs.debug (fun m -> m "root file %a" Root.pp root) ;
    let* targets, warn =
      to_str Conex_io.pp_r_err (IO.read_targets io root (not no_opam) id')
    in
    List.iter (fun msg -> Logs.warn (fun m -> m "%s" msg)) warn ;
    let keys =
      M.fold
        (fun k v acc -> M.add k (Key.to_string v) acc)
        targets.Targets.keys M.empty
    in
    let* dgst = Expression.hash V.raw_digest keys targets.Targets.valid in
    Logs.app (fun m -> m "hash %a" Digest.pp dgst) ;
    Ok ())

let compute _ dry repodir id pkg root_file no_opam =
  msg_to_cmdliner (
    let* io = repo ~rw:(not dry) repodir in
    let* root, warn = to_str Conex_io.pp_r_err (IO.read_root io root_file) in
    List.iter (fun msg -> Logs.warn (fun m -> m "%s" msg)) warn ;
    Logs.debug (fun m -> m "root file %a" Root.pp root) ;
    let path = Option.fold ~none:[] ~some:(fun p -> [ p ]) pkg in
    let* targets =
      IO.compute_checksum ~prefix:root.Root.datadir io (not no_opam) V.raw_digest path
    in
    let out =
      let raw = List.map Target.wire_raw targets in
      M.add "targets" (Wire.List raw) M.empty
    in
    Logs.app (fun m -> m "computed targets: %s" (Conex_opam_encoding.encode out)) ;
    let* id' = Option.to_result ~none:"requires id for writing" id in
    let* t, warn =
      to_str Conex_io.pp_r_err (IO.read_targets io root (not no_opam) id')
    in
    List.iter (fun msg -> Logs.warn (fun m -> m "%s" msg)) warn ;
    let t' = { t with Targets.targets = t.Targets.targets @ targets } in
    IO.write_targets io root t')

let sign _ dry repodir id no_incr root_file no_opam =
  Mirage_crypto_rng_unix.use_default () ;
  msg_to_cmdliner (
    let* priv, id' = init_priv_id id in
    let* io = repo ~rw:(not dry) repodir in
    let* root, warn = to_str Conex_io.pp_r_err (IO.read_root io root_file) in
    List.iter (fun msg -> Logs.warn (fun m -> m "%s" msg)) warn ;
    Logs.debug (fun m -> m "root is %a" Root.pp root) ;
    let* targets, warn =
      to_str Conex_io.pp_r_err (IO.read_targets io root (not no_opam) id')
    in
    let* () =
      match M.find_opt id' targets.Targets.keys with
      | None -> Error ("key for " ^ id' ^ " not present in targets file")
      | Some _ -> Ok ()
    in
    List.iter (fun msg -> Logs.warn (fun m -> m "%s" msg)) warn ;
    let* targets' =
      match no_incr, Uint.succ targets.Targets.counter with
      | true, _ -> Ok targets
      | false, (false, counter) -> Ok { targets with Targets.counter }
      | false, (true, _) -> Error "couldn't increment counter"
    in
    let* signature = PRIV.sign (Targets.wire_raw targets') now id' priv in
    let targets'' = Targets.add_signature targets' id' signature in
    IO.write_targets io root targets'')

let help _ _ _ _ man_format cmds = function
  | None -> `Help (`Pager, None)
  | Some t when List.mem t cmds -> `Help (man_format, Some t)
  | Some _ -> List.iter print_endline cmds; `Ok ()

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let docs = Keys.docs

let help_secs = [
 `S "GENERAL";
 `P "$(mname) is a tool for managing cryptographically signed community repositories.";
 `P "The signing metadata is kept in the same repository.";
 `S docs;
 `P "These options are common to all commands.";
 `S "SEE ALSO";
 `P "Use `$(mname) $(i,COMMAND) --help' for help on a single command.";
 `S "BUGS"; `P "Please report bugs at https://github.com/hannesm/conex.";]

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ~docs ()
        $ Logs_cli.level ~docs ())

let sign_cmd =
  let doc = "sign targets file with provided key" in
  let man =
    [`S "DESCRIPTION";
     `P "Cryptographically signs queued changes to your resource list."]
  in
  let term =
    Term.(ret Conex_opts.(const sign $ setup_log $ Keys.dry $ Keys.repo $ Keys.id $ Keys.no_incr $ Keys.root $ Keys.no_opam))
  and info = Cmd.info "sign" ~doc ~man
  in
  Cmd.v info term

let status_cmd =
  let doc = "information about provided targets file" in
  let man =
    [`S "DESCRIPTION";
     `P "Shows information targets file."]
  in
  let term =
    Term.(ret Conex_opts.(const status $ setup_log $ Keys.repo $ Keys.id $ Keys.root $ Keys.no_opam))
  and info = Cmd.info "status" ~doc ~man
  in
  Cmd.v info term

let create_cmd =
  let doc = "create a targets file" in
  let man =
    [`S "DESCRIPTION";
     `P "Creates a fresh targets file."]
  in
  let term =
    Term.(ret Conex_opts.(const create $ setup_log $ Keys.repo $ Keys.id $ Keys.dry $ Keys.root $ Keys.no_opam))
  and info = Cmd.info "create" ~doc ~man
  in
  Cmd.v info term

let hash_cmd =
  let doc = "create a hash of the valid expression in a targets file" in
  let man =
    [`S "DESCRIPTION";
     `P "Hash targets valid expression file."]
  in
  let term =
    Term.(ret Conex_opts.(const hash $ setup_log $ Keys.repo $ Keys.id $ Keys.root $ Keys.no_opam))
  and info = Cmd.info "hash" ~doc ~man
  in
  Cmd.v info term

let compute_cmd =
  let doc = "compute checksums for targets file" in
  let man =
    [`S "DESCRIPTION";
     `P "Computes checksums."]
  in
  let term =
    Term.(ret Conex_opts.(const compute $ setup_log $ Keys.dry $ Keys.repo $ Keys.id $ Keys.package $ Keys.root $ Keys.no_opam))
  and info = Cmd.info "compute" ~doc ~man
  in
  Cmd.v info term

let help_cmd =
  let topic =
    let doc = "The topic to get help on. `topics' lists the topics." in
    Arg.(value & pos 0 (some string) None & info [] ~docv:"TOPIC" ~doc)
  in
  Term.(ret Conex_opts.(const help $ setup_log $ Keys.dry $ Keys.repo $ Keys.id $ Arg.man_format $ Term.choice_names $ topic))

let cmds = [ status_cmd ; sign_cmd ; create_cmd ; compute_cmd ; hash_cmd ]

let () =
  let doc = "Manage targets files of a signed community repository" in
  let man = help_secs in
  let info = Cmd.info "conex_targets" ~version:"%%VERSION_NUM%%" ~sdocs:docs ~doc ~man in
  let group = Cmd.group ~default:help_cmd info cmds in
  exit (Cmd.eval group)
