
type 'a fmt = Format.formatter -> 'a -> unit

let pp_list pe ppf xs =
  match xs with
  | [] -> Format.pp_print_string ppf "empty"
  | xs ->
    Format.pp_print_string ppf "[" ;
    let rec p1 = function
      | [] -> Format.pp_print_string ppf "]" ;
      | [x] -> Format.fprintf ppf "%a]" pe x
      | x::xs -> Format.fprintf ppf "%a;@ " pe x ; p1 xs
    in
    p1 xs
[@@coverage off]

module S = struct
  include Set.Make(String)

  let pp fmt t =
    pp_list Format.pp_print_string fmt (elements t)
  [@@coverage off]

  let of_list es = List.fold_right add es empty
end

let str_pp pp e = Format.asprintf "%a" pp e

let ( let* ) = Result.bind

let guard p err = if p then Ok () else Error err

let rec foldM f n = function
  | [] -> Ok n
  | x::xs ->
    let* n' = f n x in
    foldM f n' xs

let rec iterM f = function
  | [] -> Ok ()
  | x::xs ->
    let* () = f x in
    iterM f xs

let foldS f a s =
  S.fold (fun id r ->
      let* r = r in
      f r id) s (Ok a)

let err_to_str pp = function
  | Ok a -> Ok a
  | Error e -> Error (str_pp pp e)

module String = struct
  type t = string

  let cuts sep str =
    String.split_on_char sep str

  let cut sep str =
    match cuts sep str with
    | [] -> None
    | [ _ ] -> None
    | [ a ; b ] -> Some (a, b)
    | a :: xs -> Some (a, String.concat (String.make 1 sep) xs)

  let slice ?(start = 0) ?stop str =
    let stop = match stop with
      | None -> String.length str
      | Some x -> x
    in
    let len = stop - start in
    String.sub str start len

  external compare_strings : string -> string -> int -> int = "conex_compare_string" [@@noalloc]

  let is_prefix ~prefix str =
    let pl = String.length prefix in
    if String.length str < pl then
      false
    else
      compare_strings str prefix pl = 0

  let lowercase_char = function
    | 'A' .. 'Z' as c -> char_of_int (int_of_char c + 0x20)
    | c -> c

  let to_lower s =
    let last = pred (String.length s)
    and bs = Bytes.of_string s
    in
    for k = 0 to last do
      Bytes.set bs k (lowercase_char (Bytes.get bs k))
    done ;
    Bytes.to_string bs

  let ascii_char ?(p = fun _ -> false) = function
    | '0' .. '9'
    | 'A' .. 'Z'
    | 'a' .. 'z' -> true
    | x -> p x

  let is_ascii ?p s =
    let last = pred (String.length s) in
    let res = ref true in
    for k = 0 to last do
      res := !res && ascii_char ?p (String.get s k)
    done;
    !res

  let trim = String.trim

  let get = String.get

  let concat = String.concat

  let compare = String.compare

  let length = String.length

  let compare_insensitive a b =
    compare (to_lower a) (to_lower b)

  let equal = String.equal

  let get_uint8 = String.get_uint8
end

module Uint = struct
  type t = int64

  let zero = 0L

  let max = -1L (* this is 0xFFFFFFFFFFFFFFFF *)

  let compare a b =
    Int64.(compare (sub a min_int) (sub b min_int))

  let succ x =
    if x = max then
      (true, 0L)
    else
      (false, Int64.succ x)

  let to_string s = Printf.sprintf "0x%LX" s

  let pp ppf i = Format.pp_print_string ppf (to_string i) [@@coverage off]

  let decimal s = Printf.sprintf "%Lu" s

  let of_string s =
    try Some (Int64.of_string s) with Failure _ -> None

  let of_float f =
    if f < 0. then
      None
    else
      try Some (Int64.of_float f) with Failure _ -> None

  let of_int_exn i =
    if i < 0 then
      invalid_arg "cannot convert integers smaller than 0"
    else
      Int64.of_int i

  let of_int i = try Some (of_int_exn i) with Failure _ -> None

end

module Uint_map = struct
  include Map.Make(Uint)
end

module M = struct
  include Map.Make(String)

  let pp pp_e ppf m =
    iter (fun k v -> Format.fprintf ppf "%s -> %a@ " k pp_e v) m
  [@@coverage off]
end

let rec filter_map ~f = function
  | []    -> []
  | x::xs ->
      match f x with
      | None    ->       filter_map ~f xs
      | Some x' -> x' :: filter_map ~f xs

(* this is stripped down from Logs library *)
module type LOGS = sig
  module Tag : sig
    type set
  end

  type ('a, 'b) msgf =
    (?header:string -> ?tags:Tag.set ->
     ('a, Format.formatter, unit, 'b) format4 -> 'a) -> 'b
  type 'a log = ('a, unit) msgf -> unit

  type src

  val warn_count : unit -> int

  val debug : ?src:src -> 'a log
  val info : ?src:src -> 'a log
  val warn : ?src:src -> 'a log
end

type file_type = File | Directory

type path = string list

let root = []

let non_path = [ ".." ; "." ; "" ; "/" ]

let path_to_string path =
  assert (not (List.exists (fun s -> List.mem s non_path) path)) ;
  List.fold_left Filename.concat "" path

let string_to_path_exn str =
  let segments = String.cuts '/' str in
  let segs = match segments with
    | ""::xs -> xs
    | xs -> xs
  in
  if List.exists (fun s -> List.mem s non_path) segs then
    invalid_arg "invalid path"
  else
    segs

let string_to_path str =
  try Ok (string_to_path_exn str) with
  | Invalid_argument m -> Error m

let path_equal a b =
  let str_eq a b = String.compare a b = 0 in
  try List.for_all2 str_eq a b with _ -> false

let rec subpath ~parent b =
  let str_eq a b = String.compare a b = 0 in
  match parent, b with
  | [], [] -> false
  | [], _ -> true
  | _, [] -> false
  | hd::tl, hd'::tl' -> if str_eq hd hd' then subpath ~parent:tl tl' else false

let rec strip_prefix ~prefix p =
  match prefix, p with
  | [], xs -> Some xs
  | hd::tl, hd'::tl' ->
    if String.compare hd hd' = 0 then strip_prefix ~prefix:tl tl' else None
  | _, [] -> None

let pp_path fmt p =
  Format.pp_print_string fmt (path_to_string p)
[@@coverage off]

type item = file_type * string

module Tree = struct
  type 'a t = Node of 'a list * 'a t M.t

  let rec equal eq (Node (del, map)) (Node (del', map')) =
    (try List.for_all2 eq del del' with _ -> false) &&
    M.equal (equal eq) map map'

  let empty = Node ([], M.empty)

  let is_empty = function
    | Node ([], m) when M.is_empty m -> true
    | Node (_, _) -> false

  let rec sub path t = match path, t with
    | [], n -> n
    | hd::tl, Node (_, m) -> match M.find_opt hd m with
      | None -> empty
      | Some n -> sub tl n

  let fold f acc root =
    let rec doit path (Node (v, map)) acc =
      let acc' = f path v acc in
      M.fold (fun k v acc -> doit (path @ [k]) v acc) map acc'
    in
    doit [] root acc

  let pp pp_e ppf node =
    let rec pp prefix ppf (Node (dels, map)) =
      let pp_map ppf map =
        List.iter (fun (key, node) ->
            let prefix' = prefix ^ "/" ^ key in
            Format.fprintf ppf "@[<2>%s@ ->@ %a@]@,"
              prefix' (pp prefix') node)
          (M.bindings map)
      in
      Format.fprintf ppf "@[<2>values:@ %a@.%a@,@]@,"
        (pp_list pp_e) dels
        pp_map map
    in
    (pp "") ppf node
  [@@coverage off]

  let rec lookup path (Node (dels, map)) =
    match path with
    | [] -> Some dels
    | hd::tl -> match M.find_opt hd map with
      | None -> None
      | Some x -> lookup tl x

  let lookup_prefix path node =
    let rec lookup sofar path (Node (dels, map)) =
      let ext = match dels with [] -> sofar | d -> d in
      match path with
      | [] -> ext
      | hd::tl -> match M.find_opt hd map with
        | None -> ext
        | Some x -> lookup ext tl x
    in
    lookup [] path node

  let rec insert path value (Node (dels, map)) =
    match path with
    | [] -> Node (dels @ [ value ], map)
    | hd::tl ->
      let n = match M.find_opt hd map with
        | None -> empty
        | Some x -> x
      in
      let res = insert tl value n in
      Node (dels, M.add hd res map)
end

let days_since_epoch (year, month, day) =
  (* following https://www.tondering.dk/claus/cal/julperiod.php#formula we
     compute the julian days of the provided date, and subtract the POSIX epoch
     from it. *)
  let open Int64 in
  let year = of_int year and month = of_int month and day = of_int day in
  let epoch = 2440588L in
  let a = div (sub 14L month) 12L in
  let y = sub (add year 4800L) a in
  let m = sub (add month (mul 12L a)) 3L in
  let m' = div (add (mul 153L m) 2L) 5L in
  let y' = mul 365L y in
  let y'' = div y 4L in
  let y''' = div y 100L in
  let y'''' = div y 400L in
  sub (sub (add (sub (add (add (add day m') y') y'') y''') y'''') 32045L) epoch

let timestamp_to_int64 ts =
  let ( let* ) = Result.bind in
  let* date, time =
    Option.to_result
      ~none:"couldn't decode timestamp, missing 'T'"
      (String.cut 'T' ts)
  in
  let* date =
    match String.cuts '-' date with
    | [ year ; month ; day ] ->
      let* () =
        guard (String.length year = 4)
          "couldn't decode timestamp: year not 4 digits"
      in
      let* y, m, d =
        try Ok (int_of_string year, int_of_string month, int_of_string day)
        with
          Failure _ -> Error "couldn't decode timestamp: bad date (int_of_string)"
      in
      let* () = guard (m > 0 && m <= 12) "couldn't decode timestamp: bad month" in
      let* () = guard (d > 0 && d <= 31) "couldn't decode timestamp: bad day" in
      Ok (y, m, d)
    | _ -> Error "couldn't decode timestamp: date not a triple"
  in
  let* s =
    let* time, offset =
      match String.cut 'Z' time with
      | Some (time, "") -> Ok (time, 0L)
      | Some (_, _) ->
        Error "couldn't decode timestamp: bad time offset ('Z' at arbitrary position)"
      | None ->
        let* time, sign, offset =
          match String.cut '+' time, String.cut '-' time with
          | None, None -> Error "couldn't decode timestamp: no offset present"
          | Some _, Some _ -> Error "couldn't decode timestamp: both '+' and '-' present"
          | Some (time, off), None -> Ok (time, 1L, off)
          | None, Some (time, off) -> Ok (time, -1L, off)
        in
        let* off =
          let* h, m =
            Option.to_result ~none:"couldn't decode timestamp: bad offset"
              (String.cut ':' offset)
          in
          let* h, m =
            try Ok (int_of_string h, int_of_string m) with
              Failure _ -> Error "couldn't decode timestamp: offset not a number"
          in
          let* () =
            guard (h >= 0 && h <= 23)
              "couldn't decode timestamp: offset hour out of range"
          in
          let* () =
            guard (m >= 0 && m <= 59)
              "couldn't decode timestamp: offset minute out of range"
          in
          Ok Int64.(mul (add (mul (of_int h) 60L) (of_int m)) 60L)
        in
        Ok (time, Int64.mul sign off)
    in
    let* s =
      match String.cuts ':' time with
      | [ hour ; minute ; second ] ->
        let* h, m, s =
          try Ok (int_of_string hour, int_of_string minute, int_of_string second)
          with
            Failure _ -> Error "couldn't decode timestamp: bad date (int_of_string)"
        in
        let* () = guard (h >= 0 && h <= 23) "couldn't decode timestamp: bad hour" in
        let* () = guard (m >= 0 && m <= 59) "couldn't decode timestamp: bad minute" in
        let* () = guard (s >= 0 && s <= 60) "couldn't decode timestamp: bad second" in
        Ok Int64.(add (mul (add (mul (of_int h) 60L) (of_int m)) 60L) (of_int s))
      | _ -> Error "couldn't decode timestamp: bad time"
    in
    Ok (Int64.add s offset)
  in
  let seconds_in_a_day = 86400L in (* 24 * 60 * 60 *)
  let r = Int64.(add (mul (days_since_epoch date) seconds_in_a_day) s) in
  let* () = guard (r > 0L) "couldn't decode timestamp: negative" in
  Ok r
