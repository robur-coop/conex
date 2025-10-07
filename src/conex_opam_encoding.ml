open Conex_utils
open Conex_resource

module OpamParserTypes = OpamParserTypes.FullPos

let ( let* ) = Result.bind

let np pelem =
  let pos = OpamParserTypes.{ filename = ""; start = (0, 0); stop = (0, 0) } in
  OpamParserTypes.{ pelem; pos }

let rec encode_s x =
  np (match x with
      | Wire.Map s ->
        if s = M.empty then
          OpamParserTypes.Ident "emptymap"
        else
          let data =
            np (M.fold (fun k v acc ->
                let ele =
                  OpamParserTypes.(List (np [ np (Ident k) ; encode_s v ]))
                in
                np ele :: acc)
                s [])
      in
      OpamParserTypes.List data
      | Wire.List l -> OpamParserTypes.List (np (List.map encode_s l))
      | Wire.Identifier i -> OpamParserTypes.Ident i
      | Wire.Data s -> OpamParserTypes.String s
      | Wire.Bigint i -> OpamParserTypes.Ident (Uint.to_string i)
      | Wire.Smallint i -> OpamParserTypes.Int i
      | Wire.Pair (i, s) -> OpamParserTypes.Group (np [ encode_s i ; encode_s s ])
      | Wire.And (a, b) -> OpamParserTypes.Logop (np `And, encode_s a, encode_s b)
      | Wire.Or (a, b) -> OpamParserTypes.Logop (np `Or, encode_s a, encode_s b))

let encode t =
  let file_contents =
    M.fold (fun k v acc ->
        np (OpamParserTypes.Variable (np k, encode_s v)) :: acc)
      t []
  in
  let file = { OpamParserTypes.file_contents ; file_name = "" } in
  (* TODO use OpamPrinter.Preserved.items txt orig f here, requires  old data *)
  Format.asprintf "%a" OpamPrinter.FullPos.format_opamfile file

let rec decode_s s =
  match s.OpamParserTypes.pelem with
  | OpamParserTypes.Ident data ->
    if String.is_prefix ~prefix:"0x" data then
      match Uint.of_string data with
      | None -> Error ("cannot parse unsigned integer: " ^ data)
      | Some x -> Ok (Wire.Bigint x)
    else if data = "emptymap" then
      Ok (Wire.Map M.empty)
    else
      Ok (Wire.Identifier data)
  | OpamParserTypes.String s -> Ok (Wire.Data (String.trim s))
  | OpamParserTypes.List { OpamParserTypes.pelem = []; _} -> Ok (Wire.List [])
  | OpamParserTypes.List { OpamParserTypes.pelem = l; _} ->
    let is_pair = function
      | { OpamParserTypes.pelem = OpamParserTypes.List { OpamParserTypes.pelem =
           [{ OpamParserTypes.pelem = OpamParserTypes.Ident _; _} ; _]; _}; _} -> true
      | _ -> false
    in
    if List.for_all is_pair l then
      let* map =
        List.fold_left (fun m xs ->
            let* m = m in
            match xs.OpamParserTypes.pelem with
              OpamParserTypes.List { OpamParserTypes.pelem =
                                       [{ OpamParserTypes.pelem = OpamParserTypes.Ident (k); _} ; v ]; _} ->
              let* v = decode_s v in
              Ok (M.add (String.trim k) v m)
            | _ -> Error "can not happen")
          (Ok M.empty) l
      in
      Ok (Wire.Map map)
    else
      let* xs =
        List.fold_left (fun xs s ->
            let* xs = xs in
            let* x = decode_s s in
            Ok (x :: xs))
          (Ok []) l
      in
      Ok (Wire.List (List.rev xs))
  | OpamParserTypes.Int i -> Ok (Wire.Smallint i)
  | OpamParserTypes.Group { OpamParserTypes.pelem =
       [{ OpamParserTypes.pelem = OpamParserTypes.Logop (op, a, b); _}]; _} ->
    let* a = decode_s a in
    let* b = decode_s b in
    begin match op.OpamParserTypes.pelem with
      | `And -> Ok (Wire.And (a, b))
      | `Or -> Ok (Wire.Or (a, b))
    end
  | OpamParserTypes.Logop (op, a, b) ->
    let* a = decode_s a in
    let* b = decode_s b in
    begin match op.OpamParserTypes.pelem with
      | `And -> Ok (Wire.And (a, b))
      | `Or -> Ok (Wire.Or (a, b))
    end
  | OpamParserTypes.Group { OpamParserTypes.pelem = [a ; f]; _} ->
    let* a = decode_s a in
    let* f = decode_s f in
    Ok (Wire.Pair (a, f))
  | _ -> Error "unexpected thing while decoding"

let decode data =
  let* file =
    try Ok (OpamParser.FullPos.string data "noname") with
      Parsing.Parse_error -> Error "parse error"
  in
  let items = file.OpamParserTypes.file_contents in
  List.fold_left (fun acc v ->
      let* acc = acc in
      match v.OpamParserTypes.pelem with
      | OpamParserTypes.Section _ -> Error "unexpected section"
      | OpamParserTypes.Variable (k, v) ->
        let* v = decode_s v in
        Ok (M.add k.OpamParserTypes.pelem v acc))
    (Ok M.empty) items
