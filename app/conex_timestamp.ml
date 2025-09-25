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

let status _ repodir root_file id timestamp_expiry =
  Conex_opts.msg_to_cmdliner (
    let* io, repo = io_repo ~rw:false repodir root_file in
    let* _ts = C.verify_timestamp ?id io repo ~timestamp_expiry ~now in
    Ok ())

let time_id id repo =
  let* time_id = Conex_repository.timestamp repo in
  match id, time_id with
  | None, None -> Error "neither ID provided nor a timestamp role in root file present"
  | None, Some (time_id, _, _) ->
    Logs.info (fun m -> m "using %a (as specified in root file)" pp_id time_id);
    Ok time_id
  | Some id, None ->
    Logs.info (fun m -> m "using %a (none specified in root file)" pp_id id);
    Ok id
  | Some id, Some (time_id, _, _) ->
    if not (id_equal id time_id) then
      Logs.warn (fun m -> m "using specified id %a, but in root file %a is specified"
                    pp_id id pp_id time_id);
    Ok id

let create _ dry repodir root_file id =
  Conex_opts.msg_to_cmdliner (
    let* io, repo = io_repo ~rw:(not dry) repodir root_file in
    let* id = time_id id repo in
    let* snap = Conex_repository.snapshot repo in
    let targets =
      match snap with
      | None ->
        Logs.warn (fun m -> m "no snapshots found in root file");
        []
      | Some (key, _, _) ->
        let path = Conex_repository.keydir repo @ [ key ] in
        match IO.compute_checksum_file io V.raw_digest path with
        | Ok target -> [ target ]
        | Error msg ->
          Logs.warn (fun m -> m "error %s while computing checksum for key %s"
                        msg key);
          []
    in
    let old_ts, warn = match IO.read_timestamp io id with
      | Ok ts -> ts
      | Error e ->
        Logs.warn (fun m -> m "error %a while reading timestamp" Conex_io.pp_r_err e);
        Timestamp.t now id, []
    in
    List.iter
      (fun w -> Logs.warn (fun m -> m "warning while reading timestamp: %s" w))
      warn;
    let ts =
      Timestamp.t ~counter:old_ts.Timestamp.counter
        ~epoch:old_ts.Timestamp.epoch
        ~keys:old_ts.Timestamp.keys
        ~targets now id
    in
    Logs.app (fun m -> m "timestamp file %a" Timestamp.pp ts) ;
    IO.write_timestamp io ts)

let sign _ dry repodir id no_incr root_file =
  Mirage_crypto_rng_unix.use_default () ;
  Conex_opts.msg_to_cmdliner (
    let* io, repo = io_repo ~rw:(not dry) repodir root_file in
    let* time_id = time_id id repo in
    let* priv, id' = init_priv_id (Some time_id) in
    let* ts, warn = to_str Conex_io.pp_r_err (IO.read_timestamp io id') in
    List.iter
      (fun w -> Logs.warn (fun m -> m "warning while reading timestamp: %s" w))
      warn;
    let* ts' =
      match no_incr, Uint.succ ts.Timestamp.counter with
      | false, (true, _) -> Error "couldn't increment counter"
      | true, _ -> Ok ts
      | false, (false, counter) -> Ok { ts with Timestamp.counter }
    in
    let* signature =
      PRIV.sign (Timestamp.wire_raw ts') now id' `RSA_PSS_SHA256 priv
    in
    let ts'' = Timestamp.add_signature ts' id' signature in
    IO.write_timestamp io ts'')

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
  let doc = "sign timestamp file with provided key" in
  let man =
    [`S "DESCRIPTION";
     `P "Cryptographically signs the timestamp file."]
  in
  let term =
    Term.(ret Conex_opts.(const sign $ setup_log $ Keys.dry $ Keys.repo $ Keys.id $ Keys.no_incr $ Keys.root))
  and info = Cmd.info "sign" ~doc ~man
  in
  Cmd.v info term

let status_cmd =
  let doc = "information about provided timestamp file" in
  let man =
    [`S "DESCRIPTION";
     `P "Shows information about the timestamp file. Th provided ID is used as \
         timestamp identifier. The timestamp file is verified. If a timestamp \
         role is present in the root file, it is validated."]
  in
  let term =
    Term.(ret Conex_opts.(const status $ setup_log $ Keys.repo $ Keys.root $ Keys.id $ Keys.timestamp_expiry))
  and info = Cmd.info "status" ~doc ~man
  in
  Cmd.v info term

let create_cmd =
  let doc = "create an empty timestamp file" in
  let man =
    [`S "DESCRIPTION";
     `P "Creates a fresh timestamp file."]
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
  let doc = "Manage timestamp file of a signed community repository" in
  let man = help_secs in
  let info = Cmd.info "conex_timestamp" ~version:"%%VERSION_NUM%%" ~sdocs:docs ~doc ~man in
  let group = Cmd.group ~default:help_cmd info cmds in
  exit (Cmd.eval group)
