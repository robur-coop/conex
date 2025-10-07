open Conex_utils
open Conex_io

(* this a very basic implementation, far from being general:
   - only a single (well-formed) patch file is used for creating a diff provider
*)
let target = function
  | Patch.Edit (_, name)
  | Create name
  | Git_ext (_, name, Rename_only _)
  | Git_ext (_, name, Create_only) -> Some name
  | Delete _
  | Git_ext (_, _, Delete_only) -> None

let source = function
  | Patch.Edit (old, _)
  | Delete old
  | Git_ext (old, _, Rename_only _)
  | Git_ext (old, _, Delete_only) -> Some old
  | Create _
  | Git_ext (_, _, Create_only) -> None

module FS = Set.Make(struct
    type t = file_type * string
    let compare (t, v) (t', v') = match t, t' with
      | File, File | Directory, Directory -> String.compare v v'
      | File, Directory -> 1 | Directory, File -> -1
  end)

let apply provider (diffs : Patch.t list) =
  let find_diff f path =
    List.find_opt (fun x ->
        match f x.Patch.operation with
        | None -> false
        | Some path' -> path_equal (string_to_path_exn path') path)
      diffs
  in
  let read path =
    match find_diff target path, find_diff source path with
    | None, None -> provider.read path
    | None, Some _ -> Error "no data"
    | Some diff, _ ->
      let res_patch old = match Patch.patch ~cleanly:true old diff with
        | None -> Error "no data"
        | Some data -> Ok data
      in
      match source diff.operation with
      | None -> res_patch None
      | Some x -> match provider.read (string_to_path_exn x) with
        | Error x -> Error x
        | Ok data -> res_patch (Some data)
  and file_type path =
    match find_diff target path, find_diff source path with
    | None, None -> provider.file_type path
    | None, Some _ -> Error "does not exist anymore (deleted)"
    | Some _, _ -> Ok File
  and read_dir path =
    (* this results in some empty directories which are not present on disk *)
    (* the reason is that I get the old files and directories,
       I also know the diffs (i.e. added and removed and renamed files), but
       for inspecting whether a directory is empty (i.e. all files are removed),
       I'd need the whole subdir information (prune empty ones) *)
    let old =
      Result.fold ~ok:(fun files -> FS.of_list files) ~error:(fun _ -> FS.empty)
        (provider.read_dir path)
    in
    let drop_pre dir path' =
      let rec dropit a b = match a, b with
        | [], [ x ] -> Some (File, x)
        | [], x::_ -> if dir then Some (Directory, x) else None
        | x::xs, y::ys when String.equal x y -> dropit xs ys
        | _ -> None
      in
      dropit path (string_to_path_exn path')
    and opt_add x xs = Option.fold ~none:xs ~some:(fun x -> FS.add x xs) x
    and opt_rem x xs = Option.fold ~none:xs ~some:(fun x -> FS.remove x xs) x
    in
    let stuff =
      List.fold_left (fun acc d ->
          match d.Patch.operation with
          | Patch.Create name | Git_ext (_, name, Create_only) ->
            opt_add (drop_pre true name) acc
          | Edit (old, name) ->
            if String.equal old name then
              opt_add (drop_pre true name) acc
            else
              opt_rem (drop_pre false old) (opt_add (drop_pre true name) acc)
          | Git_ext (old, name, Rename_only _) ->
            opt_rem (drop_pre false old) (opt_add (drop_pre true name) acc)
          | Delete old | Git_ext (old, _, Delete_only) ->
            opt_rem (drop_pre false old) acc)
        old diffs
    in
    Ok (FS.elements stuff)
  and write _ _ = Error "read only"
  and exists path =
    match find_diff target path, find_diff source path with
    | None, None -> provider.exists path
    | Some _, _ -> true
    | None, Some _ -> false
  and basedir = provider.basedir
  and description = "Patch provider"
  in
  { basedir ; description ; file_type ; read ; write ; read_dir ; exists }

let apply_diff io data =
  (* TODO check whether ~p:0 is the right thing for opam *)
  let diffs = Patch.parse ~p:0 data in
  apply io diffs, diffs

(* TODO which equality to use here? is = ok? *)
let ids root keydir diffs =
  let ( let* ) = Result.bind in
  List.fold_left (fun acc diff ->
      let add_name name (r, ids) =
        let* path = string_to_path name in
        if subpath ~parent:keydir path then
          (* TODO according to here, keydir must be flat! *)
          match List.rev path with
          | id :: _ -> Ok (r, S.add id ids)
          | [] -> Error "empty keydir path?"
        else match path with
          | [ x ] when x = root -> Ok (true, ids)
          | _ -> Ok (r, ids)
      in
      let* r, ids = acc in
      match diff.Patch.operation with
      | Create a | Delete a -> add_name a (r, ids)
      | Git_ext (a, b, _) | Edit (a, b) ->
        let* ids' = add_name a (r, ids) in
        add_name b ids')
    (Ok (false, S.empty)) diffs
