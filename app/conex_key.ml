open Conex_resource

open Conex_opts
open Conex_mc

let ( let* ) = Result.bind

let jump _ id alg force pub =
  Mirage_crypto_rng_unix.use_default () ;
  msg_to_cmdliner (
    let* id = Option.to_result ~none:"need an id" id in
    let fp k =
      let public = PRIV.pub_of_priv k in
      Logs.app (fun m -> m "%s key %s created %s keyid %s"
                   (Key.alg_to_string (PRIV.alg k))
                   (PRIV.id k) (PRIV.created k)
                   (Digest.to_string (Key.keyid V.raw_digest public))) ;
      if pub then
        Logs.app (fun m -> m "public key: %a@.%s"
                     Conex_resource.Key.pp public
                     (Conex_opam_encoding.encode (Key.wire public))) ;
      Ok ()
    in
    let gen_or_err () =
      let* t = PRIV.generate to_ts alg id () in
      Logs.app (fun m -> m "generated fresh key") ;
      fp t
    in
    if force
    then gen_or_err ()
    else match PRIV.read to_ts id with
      | Ok key -> fp key
      | Error `None -> gen_or_err ()
      | Error e -> Error (Fmt.to_to_string PRIV.pp_r_err e))

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let docs = Keys.docs

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ~docs ()
        $ Logs_cli.level ~docs ())

let pub =
  let doc = "Display full public key." in
  Arg.(value & flag & info ["pub"] ~docs ~doc)

let cmd =
  let doc = "key management" in
  let term = Term.(ret (const jump $ setup_log $ Keys.id $ Keys.key_alg $ Keys.force $ pub))
  and info = Cmd.info "conex_key" ~version:"%%VERSION_NUM%%" ~doc
  in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
