open Conex_utils
open Conex_unix_persistency
open Conex_io

let ( let* ) = Result.bind

let realpath dir =
  (* Unix.realpath is only 4.13+ *)
  let cwd_chdir dir =
    let cwd =
      try Sys.getcwd ()
      with Sys_error _ -> Filename.get_temp_dir_name ()
    in
    Unix.chdir dir;
    cwd
  in
  try cwd_chdir (cwd_chdir dir) with Unix.Unix_error _ -> dir

let fs_provider basedir =
  let basedir = realpath basedir in
  let* () =
    if not (exists basedir) then
      mkdir basedir
    else
      Ok ()
  in
  let get path = path_to_string (basedir :: path) in
  let ensure_dir path =
    let rec mkdir base = function
      | [] -> Ok ()
      | [_] -> Ok ()
      | x::xs ->
         let path = base @ [x] in
         let str = path_to_string path in
         let* () =
           if not (exists str) then
             Conex_unix_persistency.mkdir (path_to_string path)
           else
             Ok ()
         in
         let* ft = file_type str in
         match ft with
         | Directory -> mkdir path xs
         | File -> Error (str ^ " is not a directory")
    in
    mkdir [basedir] path
  in
  let file_type path =
    let p = get path in
    file_type p
  and read path =
    let fn = get path in
    read_file fn
  and write path data =
    let* () = ensure_dir path in
    let nam = get path in
    write_replace nam data
  and read_dir path =
    let abs = get path in
    let* files = collect_dir abs in
    foldM (fun acc fn ->
        let fullfn = Filename.concat abs fn in
        let* ft = file_type fullfn in
        match ft with
        | File -> Ok ((File, fn) :: acc)
        | Directory -> Ok ((Directory, fn) :: acc))
      [] files
  and exists path =
    exists (get path)
  in
  Ok { basedir ; description = "File system provider" ; file_type ; read ; write ; read_dir ; exists }

let fs_ro_provider basedir =
  let* fs = fs_provider basedir in
  let write _ _ = Ok ()
  and description = "Read only file system provider"
  in
  Ok { fs with description ; write }
