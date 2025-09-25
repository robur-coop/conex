open Conex_utils
open Conex_resource
open Conex_opam_encoding

type t = {
  basedir : string ;
  description : string ;
  file_type : path -> (file_type, string) result ;
  read : path -> (string, string) result ;
  write : path -> string -> (unit, string) result ;
  read_dir : path -> (item list, string) result ;
  exists : path -> bool ;
}

let pp ppf t =
  Format.fprintf ppf "repository %s: %s" t.basedir t.description
[@@coverage off]

let ( let* ) = Result.bind

type r_err = [
  | `NotFound of typ * name
  | `ParseError of typ * name * string
  | `NameMismatch of typ * name * name
  | `InvalidPath of identifier * path
]

let pp_r_err ppf = function
  | `NotFound (res, nam) -> Format.fprintf ppf "%a (type %a) was not found in repository" pp_name nam pp_typ res
  | `ParseError (res, n, e) -> Format.fprintf ppf "parse error while parsing %a (type %a): %s" pp_name n pp_typ res e
  | `NameMismatch (res, should, is) -> Format.fprintf ppf "%a (type %a) is named %a" pp_name should pp_typ res pp_name is
  | `InvalidPath (nam, path) -> Format.fprintf ppf "%a contains an invalid path %a" pp_id nam pp_path path
[@@coverage off]

module Make (L : LOGS) = struct
  let read_root t root_file =
    Result.fold
      ~error:(fun _ -> Error (`NotFound (`Root, root_file)))
      ~ok:(fun data ->
          Result.fold
            ~error:(fun p -> Error (`ParseError (`Root, root_file, p)))
            ~ok:(fun (root, warn) ->
                let* () =
                  guard (id_equal root.Root.name root_file)
                    (`NameMismatch (`Root, root_file, root.Root.name))
                in
                Ok (root, warn))
            Result.(join (map Root.of_wire (decode data))))
      (t.read [ root_file ])

  let write_root t root =
    let id = root.Root.name in
    t.write [ id ] (encode (Root.wire root))

  let read_timestamp t timestamp_file =
    Result.fold
      ~error:(fun _ -> Error (`NotFound (`Timestamp, timestamp_file)))
      ~ok:(fun data ->
          Result.fold
            ~error:(fun p -> Error (`ParseError (`Timestamp, timestamp_file, p)))
            ~ok:(fun (timestamp, warn) ->
                let* () =
                  guard (id_equal timestamp.Timestamp.name timestamp_file)
                    (`NameMismatch (`Timestamp, timestamp_file, timestamp.Timestamp.name))
                in
                Ok (timestamp, warn))
            Result.(join (map Timestamp.of_wire (decode data))))
      (t.read [ timestamp_file ])

  let write_timestamp t timestamp =
    let id = timestamp.Timestamp.name in
    t.write [ id ] (encode (Timestamp.wire timestamp))

  let read_snapshot t snapshot_file =
    Result.fold
      ~error:(fun _ -> Error (`NotFound (`Snapshot, snapshot_file)))
      ~ok:(fun data ->
          Result.fold
            ~error:(fun p -> Error (`ParseError (`Snapshot, snapshot_file, p)))
            ~ok:(fun (snap, warn) ->
                let* () =
                  guard (id_equal snap.Snapshot.name snapshot_file)
                    (`NameMismatch (`Snapshot, snapshot_file, snap.Snapshot.name))
                in
                Ok (snap, warn))
            Result.(join (map Snapshot.of_wire (decode data))))
      (t.read [ snapshot_file ])

  let write_snapshot t snapshot =
    let id = snapshot.Snapshot.name in
    t.write [ id ] (encode (Snapshot.wire snapshot))

  let targets t root =
    match t.read_dir root.Root.keydir with
    | Error e ->
      Printf.printf "failed while listing keys with %s\n" e ;
      []
    | Ok datas ->
      List.fold_left (fun acc -> function
          | File, name -> name :: acc
          | Directory, name ->
            Printf.printf "unexpected directory %s in keydir!" name ;
            acc)
        [] datas

  let read_targets t root opam id =
    let path = root.Root.keydir @ [ id ] in
    Result.fold
      ~error:(fun _ -> Error (`NotFound (`Targets, id)))
      ~ok:(fun data ->
          Result.fold
            ~error:(fun p -> Error (`ParseError (`Targets, id, p)))
            ~ok:(fun (targets, warn) ->
                let* () =
                  guard (id_equal targets.Targets.name id)
                    (`NameMismatch (`Targets, id, targets.Targets.name))
                in
                let datadir = root.Root.datadir in
                let check_path t =
                  if opam then
                    guard (Target.valid_opam_path datadir t) (`InvalidPath (id, t.Target.filename))
                  else
                    Ok ()
                in
                let* () = iterM check_path targets.Targets.targets in
                Ok (targets, warn))
            Result.(join (map Targets.of_wire (decode data))))
      (t.read path)

  let write_targets t root targets =
    let path = root.Root.keydir @ [ targets.Targets.name ] in
    Printf.printf "writing %s\n" (path_to_string path) ;
    t.write path (encode (Targets.wire targets))

  let digest_len f data =
    let digest = f data
    and size = Uint.of_int_exn (String.length data)
    in
    (digest, size)

  let target f filename data =
    let digest, size = digest_len f data in
    { Target.digest = [ digest ] ; size ; filename }

  let compute_checksum_file t f filename =
    let* data = t.read filename in
    Ok (target f filename data)

  let compute_checksum ~prefix t opam f path =
    let rec compute_item prefix acc = function
      | Directory, name ->
        let path = prefix @ [ name ] in
        let* items = t.read_dir path in
        foldM (compute_item path) acc items
      | File, name ->
        let filename = prefix @ [ name ] in
        let* target = compute_checksum_file t f filename in
        if not opam || opam && Target.valid_opam_path prefix target then
          if not opam || opam && Target.collect_opam_file prefix target then
            Ok (target :: acc)
          else begin
            L.info (fun m -> m "ignoring %s" (String.concat "/" filename));
            Ok acc
          end
        else
          Error ("invalid path " ^ path_to_string filename)
    in
    let go pre name = compute_item (prefix @ pre) [] (Directory, name) in
    match List.rev path with
    | [] ->
      let* items = t.read_dir prefix in
      foldM (fun acc e -> match e with
          | Directory, _ -> compute_item prefix acc e
          | File, _ -> Ok acc)
        [] items
    | [ name ] -> go [] name
    | name::rest -> go (List.rev rest) name

  let compute_checksum_tree ~prefix t f =
    let rec compute_item prefix acc = function
      | Directory, name ->
        let path = prefix @ [ name ] in
        let* items = t.read_dir path in
        foldM (compute_item path) acc items
      | File, name ->
        let filename = prefix @ [ name ] in
        let* target = compute_checksum_file t f filename in
        Ok (Tree.insert filename (List.hd target.digest, target.size) acc)
    in
    let* items = t.read_dir prefix in
    foldM (compute_item prefix) Tree.empty items
end
