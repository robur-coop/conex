open Conex_utils
open Conex_resource

open Conex_mc

module IO = Conex_io.Make(Logs)

let ( let* ) = Result.bind

let io_repo ~rw repodir root_file =
  let* io = Conex_opts.repo ~rw repodir in
  let* root, warn = to_str Conex_io.pp_r_err (IO.read_root io root_file) in
  List.iter (fun msg -> Logs.warn (fun m -> m "%s" msg)) warn ;
  Logs.debug (fun m -> m "root file %a" Root.pp root) ;
  let repo = Conex_repository.create root in
  Ok (io, repo)

let status _ repodir root_file id =
  Conex_opts.msg_to_cmdliner (
    let* io, repo = io_repo ~rw:false repodir root_file in
    let* _ = C.verify_snapshot ?id io repo in
    Ok ())

let snap_id id repo =
  let* snap_id = Conex_repository.snapshot repo in
  match id, snap_id with
  | None, None -> Error "neither ID provided nor a snapshot role in root file present"
  | None, Some (snap_id, _, _) ->
    Logs.info (fun m -> m "using %a (as specified in root file)" pp_id snap_id);
    Ok snap_id
  | Some id, None ->
    Logs.info (fun m -> m "using %a (none specified in root file)" pp_id id);
    Ok id
  | Some id, Some (snap_id, _, _) ->
    if not (id_equal id snap_id) then
      Logs.warn (fun m -> m "using specified id %a, but in root file %a is specified"
                    pp_id id pp_id snap_id);
    Ok id

let create _ dry repodir root_file id =
  Conex_opts.msg_to_cmdliner (
    let* io, repo = io_repo ~rw:(not dry) repodir root_file in
    let* id = snap_id id repo in
    let* targets =
      IO.compute_checksum ~prefix:(Conex_repository.keydir repo)
        io false V.raw_digest []
    in
    let targets =
      let f =
        match Conex_repository.timestamp repo with
        | Ok (Some (tid, _, _)) -> (fun tgt_id -> not (id_equal tid tgt_id))
        | _ -> (fun _ -> true)
      in
      List.filter (fun tgt ->
          let tgt_id =
            match List.rev tgt.Target.filename with
            | hd :: _ -> hd
            | _ -> assert false
          in
          not (id_equal tgt_id id) && f tgt_id)
        targets
    in
    let old_snap, warn = match IO.read_snapshot io id with
      | Ok snap -> snap
      | Error e ->
        Logs.warn (fun m -> m "error %a while reading snapshot" Conex_io.pp_r_err e);
        Snapshot.t now id, []
    in
    List.iter
      (fun w -> Logs.warn (fun m -> m "warning while reading snapshot: %s" w))
      warn;
    let ts =
      Timestamp.t ~counter:old_snap.Snapshot.counter
        ~epoch:old_snap.Snapshot.epoch
        ~keys:old_snap.Snapshot.keys
        ~targets now id
    in
    Logs.app (fun m -> m "timestamp file %a" Timestamp.pp ts) ;
    IO.write_timestamp io ts)

let sign _ dry repodir id no_incr root_file =
  Mirage_crypto_rng_unix.use_default () ;
  Conex_opts.msg_to_cmdliner (
    let* io, repo = io_repo ~rw:(not dry) repodir root_file in
    let* snap_id = snap_id id repo in
    let* priv, id' = init_priv_id (Some snap_id) in
    let* snap, warn = to_str Conex_io.pp_r_err (IO.read_snapshot io id') in
    List.iter
      (fun w -> Logs.warn (fun m -> m "warning while reading snapshot: %s" w))
      warn;
    let* snap' =
      match no_incr, Uint.succ snap.Snapshot.counter with
      | false, (true, _) -> Error "couldn't increment counter"
      | true, _ -> Ok snap
      | false, (false, counter) -> Ok { snap with Snapshot.counter }
    in
    let* signature =
      PRIV.sign (Snapshot.wire_raw snap') now id' `RSA_PSS_SHA256 priv
    in
    let snap'' = Snapshot.add_signature snap' id' signature in
    IO.write_snapshot io snap'')

let help _ _ _ _ man_format cmds = function
  | None -> `Help (`Pager, None)
  | Some t when List.mem t cmds -> `Help (man_format, Some t)
  | Some _ -> List.iter print_endline cmds; `Ok ()

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let docs = Conex_opts.Keys.docs

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
  let doc = "sign snapshot file with provided key" in
  let man =
    [`S "DESCRIPTION";
     `P "Cryptographically signs the snapshot file."]
  in
  let term =
    Term.(ret Conex_opts.(const sign $ setup_log $ Keys.dry $ Keys.repo $ Keys.id $ Keys.no_incr $ Keys.root))
  and info = Cmd.info "sign" ~doc ~man
  in
  Cmd.v info term

let status_cmd =
  let doc = "information about provided snapshot file" in
  let man =
    [`S "DESCRIPTION";
     `P "Shows information about the snapshot file. The provided ID is used as \
         snapshot identifier. The snapshot file is verified. If a snapshot role \
         is present in the root file, it is validated."]
  in
  let term =
    Term.(ret Conex_opts.(const status $ setup_log $ Keys.repo $ Keys.root $ Keys.id))
  and info = Cmd.info "status" ~doc ~man
  in
  Cmd.v info term

let create_cmd =
  let doc = "create an empty snapshot file" in
  let man =
    [`S "DESCRIPTION";
     `P "Creates a fresh snapshot file."]
  in
  let term =
    Term.(ret Conex_opts.(const create $ setup_log $ Keys.dry $ Keys.repo $ Keys.root $ Keys.id))
  and info = Cmd.info "create" ~doc ~man
  in
  Cmd.v info term

let help_cmd =
  let topic =
    let doc = "The topic to get help on. `topics' lists the topics." in
    Arg.(value & pos 0 (some string) None & info [] ~docv:"TOPIC" ~doc)
  in
  Term.(ret Conex_opts.(const help $ setup_log $ Keys.dry $ Keys.repo $ Keys.id $ Arg.man_format $ Term.choice_names $ topic))

let cmds = [ status_cmd ; sign_cmd ; create_cmd ]

let () =
  let doc = "Manage snapshot file of a signed community repository" in
  let man = help_secs in
  let info = Cmd.info "conex_snapshot" ~version:"%%VERSION_NUM%%" ~sdocs:docs ~doc ~man in
  let group = Cmd.group ~default:help_cmd info cmds in
  exit (Cmd.eval group)
