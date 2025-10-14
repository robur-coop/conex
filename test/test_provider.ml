open Conex_utils
open Conex_io

open Common

let ( let* ) = Result.bind

module Mem = struct
  type tree = Leaf of string * string | Node of string * tree list

  let name = function Leaf (x, _) -> x | Node (x, _) -> x

  let find_e x es =
    try Some (List.find (fun n -> name n = x) es) with Not_found -> None

  let rec find t path =
    match t, path with
    | x, [p] when name x = p -> Ok x
    | _, [_] -> Error "couldn't find what you were looking for"
    | Node (_, xs), _::p'::ps ->
      (match find_e p' xs with
       | None -> Error "not found what you're looking for"
       | Some x -> find x (p'::ps))
    | _ -> Error "couldn't find"

  let rec insert t path v =
    match t, path with
    (* leaf case, just add the leaf *)
    | Node (x, xs), _::ps::[] ->
      let l = Leaf (ps, v) in
      let ns = List.filter (fun n -> name n <> ps) xs in
      Node (x, l::ns)
    (* on the route towards.. move along *)
    | Node (x, xs), _::p'::ps ->
      let node =
        match find_e p' xs with
        (* need to create an intermediary node *)
        | None ->
          let n = Node (p', []) in
          insert n (p'::ps) v
        (* follow on *)
        | Some n -> insert n (p'::ps) v
      in
      let xs = List.filter (fun n -> name n <> p') xs in
      Node (x, node::xs)
    | _ -> Alcotest.fail "should not happen"

  let find_f t path = find t ("/"::path)

  let ins t path v = insert t ("/"::path) v

  let mem_provider () : Conex_io.t =
    let root = ref (Node ("/", [])) in
    let file_type path =
      let* n = find_f !root path in
      match n with
      | Leaf _ -> Ok File
      | Node _ -> Ok Directory
    and read path =
      let* n = find_f !root path in
      match n with
      | Leaf (_, v) -> Ok v
      | _ -> Error "couldn't find what was searched for"
    and write path data =
      let r = ins !root path data in
      root := r ;
      Ok ()
    and read_dir path =
      let* n = find_f !root path in
      match n with
      | Node (_, ch) -> Ok (List.map (function Node (x, _) -> Directory, x | Leaf (x, _) -> File, x) ch)
      | Leaf _ -> Error "reading a directory, but found files"
    and exists path =
      match find_f !root path with Ok _ -> true | Error _ -> false
    in
    { basedir = "mem" ; description = "Memory provider" ; file_type ; read ; write ;read_dir ; exists }
end

let str_err =
  let module M = struct
    type t = string
    let pp ppf x = Format.pp_print_string ppf x
    let equal _ _ = true
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let ft =
  let module M = struct
    type t = file_type
    let pp ppf = function
      | File -> Format.pp_print_string ppf "file"
      | Directory -> Format.pp_print_string ppf "directory"
    let equal a b = match a, b with
      | File, File -> true
      | Directory, Directory -> true
      | _ -> false
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let it =
  let module M = struct
    type t = Conex_utils.item
    let pp ppf = function
      | File, f -> Format.fprintf ppf "file %s" f
      | Directory, d -> Format.fprintf ppf "directory %s" d
    let equal a b = match a, b with
      | (File, f), (File, g) -> f = g
      | (Directory, a), (Directory, b) -> a = b
      | _ -> false
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let empty_p () =
  let p = Mem.mem_provider () in
  Alcotest.check Alcotest.bool "no 'foo' in empty mem store" false (p.exists ["foo"]) ;
  Alcotest.check (result Alcotest.string str_err) "reading 'foo' in empty mem store" (Error "") (p.read ["foo"]) ;
  Alcotest.check (result ft str_err) "file-type of 'foo' in empty mem store" (Error "") (p.file_type ["foo"]) ;
  Alcotest.check (result (Alcotest.list it) str_err) "read_dir of 'foo' in empty mem store" (Error "") (p.read_dir ["foo"])

let basic_p () =
  let p = Mem.mem_provider () in
  Alcotest.check (result Alcotest.unit str_err) "writing 'bar' to 'foo'"
    (Ok ()) (p.write ["foo"] "bar") ;
  Alcotest.check Alcotest.bool "foo in basic store" true (p.exists ["foo"]) ;
  Alcotest.check Alcotest.bool "foo/bar not in basic store" false (p.exists ["foo";"bar"]) ;
  Alcotest.check Alcotest.bool "foobar not in basic store" false (p.exists ["foobar"]) ;
  Alcotest.check (result Alcotest.string str_err) "foo contains bar in simple store" (Ok "bar") (p.read ["foo"]) ;
  Alcotest.check (result Alcotest.unit str_err) "writing 'barf' to 'foo"
    (Ok ()) (p.write ["foo"] "barf") ;
  Alcotest.check (result Alcotest.string str_err) "foo contains barf in simple store" (Ok "barf") (p.read ["foo"]) ;
  Alcotest.check (result (Alcotest.list it) str_err) "read_dir of 'foo' in simple store" (Error "") (p.read_dir ["foo"])

let more_p () =
  let p = Mem.mem_provider () in
  Alcotest.check (result Alcotest.unit str_err) "writing 'bar' to 'packages/foo'"
    (Ok ()) (p.write ["packages"; "foo"] "bar") ;
  Alcotest.check Alcotest.bool "packages in more store" true (p.exists ["packages"]) ;
  Alcotest.check Alcotest.bool "packages/foo in more store" true (p.exists ["packages"; "foo"]) ;
  Alcotest.check Alcotest.bool "packages/foo/bar not in more store" false (p.exists ["packages"; "foo"; "bar"]) ;
  Alcotest.check (result Alcotest.unit str_err) "writing 'bar2' to 'packages/foo2'"
    (Ok ()) (p.write ["packages"; "foo2"] "bar2") ;
  Alcotest.check (result (Alcotest.list it) str_err) "read_dir of 'packages' in more mem store"
    (Ok [ File, "foo2" ; File, "foo" ]) (p.read_dir ["packages"]) ;
  Alcotest.check (result Alcotest.unit str_err) "writing 'bar3' to 'packages/foo3'"
    (Ok ()) (p.write ["packages"; "foo3"] "bar3") ;
  Alcotest.check (result Alcotest.unit str_err) "writing 'bar4' to 'packages/foo4'"
    (Ok ()) (p.write ["packages"; "foo4"] "bar4") ;
  Alcotest.check (result (Alcotest.list it) str_err) "read_dir of 'packages' in even more mem store"
    (Ok [ File, "foo4" ; File, "foo3" ; File, "foo2" ; File, "foo" ]) (p.read_dir ["packages"]) ;
  Alcotest.check (result (Alcotest.list it) str_err) "read_dir of 'packages2' in even more mem store"
    (Error "") (p.read_dir ["packages2"]) ;
  Alcotest.check (result Alcotest.string str_err) "foo contains bar in more store"
    (Ok "bar") (p.read ["packages";"foo"]) ;
  Alcotest.check (result Alcotest.string str_err) "foo2 contains bar2 in more store"
    (Ok "bar2") (p.read ["packages"; "foo2"]) ;
  Alcotest.check (result Alcotest.string str_err) "foo3 contains bar3 in more store"
    (Ok "bar3") (p.read ["packages"; "foo3"]) ;
  Alcotest.check (result Alcotest.string str_err) "foo4 contains bar4 in more store"
    (Ok "bar4") (p.read ["packages"; "foo4"]) ;
  Alcotest.check (result Alcotest.string str_err) "foo5 not contained in more store"
    (Error "") (p.read ["packages"; "foo5"]) ;
  Alcotest.check (result Alcotest.unit str_err) "writing 'foobar' to 'packages/foobar/barfoo/foobar/foo'"
    (Ok ()) (p.write ["packages"; "foobar" ; "barfoo" ; "foobar" ; "foo"] "foobar") ;
  Alcotest.check (result Alcotest.string str_err) "packages/foobar/barfoo/foobar/foo contained in more store"
    (Ok "foobar") (p.read ["packages"; "foobar" ; "barfoo" ; "foobar" ; "foo"]) ;
  Alcotest.check Alcotest.bool "packages/foobar/barfoo/foobar contained in more store"
    true (p.exists ["packages"; "foobar" ; "barfoo" ; "foobar"])

let diff_test_create () =
  let p = Mem.mem_provider () in
  let diff = {|
--- /dev/null
+++ b/packages/foo
@@ -0,0 +1 @@
+bar
|}
  in
  let d, _ = Conex_diff_provider.apply_diff p diff in
  Alcotest.check Alcotest.bool __LOC__
    true (d.exists ["packages" ; "foo"]) ;
  Alcotest.check (result (Alcotest.list it) str_err) __LOC__
    (Ok [ Directory, "packages" ]) (d.read_dir []) ;
  Alcotest.check (result (Alcotest.list it) str_err) __LOC__
    (Ok [ File, "foo" ]) (d.read_dir ["packages"]) ;
  Alcotest.check (result ft str_err) __LOC__
    (Ok File) (d.file_type ["packages" ; "foo"]) ;
  Alcotest.check (result Alcotest.string str_err) __LOC__
    (Ok "bar\n") (d.read ["packages" ; "foo"])

let diff_test_remove () =
  let p = Mem.mem_provider () in
  (match p.write ["packages" ; "foo" ] "bar\n" with
   | Ok () -> ()
   | Error _ -> assert false) ;
  let diff = {|
--- a/packages/foo
+++ /dev/null
@@ -1 +0,0 @@
-bar
|}
  in
  let d, _ = Conex_diff_provider.apply_diff p diff in
  Alcotest.check Alcotest.bool __LOC__
    false (d.exists ["packages" ; "foo"]) ;
  Alcotest.check (result (Alcotest.list it) str_err) __LOC__
    (Ok []) (d.read_dir ["packages"]) ;
  Alcotest.check (result ft str_err) __LOC__
    (Error "") (d.file_type ["packages" ; "foo"]) ;
  Alcotest.check (result Alcotest.string str_err) __LOC__
    (Error "") (d.read ["packages" ; "foo"])

let diff_test_rename () =
  let p = Mem.mem_provider () in
  (match p.write ["packages" ; "foo" ] "bar\n" with
   | Ok () -> ()
   | Error _ -> assert false) ;
  let diff = {|
--- a/packages/foo
+++ b/packages/bar
@@ -1 +1 @@
-bar
+foobar
|}
  in
  let d, _ = Conex_diff_provider.apply_diff p diff in
  Alcotest.check Alcotest.bool __LOC__
    false (d.exists ["packages" ; "foo"]) ;
  Alcotest.check Alcotest.bool __LOC__
    true (d.exists ["packages" ; "bar"]) ;
  Alcotest.check (result (Alcotest.list it) str_err) __LOC__
    (Ok [ File, "bar" ]) (d.read_dir ["packages"]) ;
  Alcotest.check (result ft str_err) __LOC__
    (Error "") (d.file_type ["packages" ; "foo"]) ;
  Alcotest.check (result ft str_err) __LOC__
    (Ok File) (d.file_type ["packages" ; "bar"]) ;
  Alcotest.check (result Alcotest.string str_err) __LOC__
    (Error "") (d.read ["packages" ; "foo"]) ;
  Alcotest.check (result Alcotest.string str_err) __LOC__
    (Ok "foobar\n") (d.read ["packages" ; "bar"])

let diff_test_edit () =
  let p = Mem.mem_provider () in
  (match p.write ["packages" ; "foo" ] "bar\n" with
   | Ok () -> ()
   | Error _ -> assert false) ;
  let diff = {|
--- a/packages/foo
+++ b/packages/foo
@@ -1 +1 @@
-bar
+foobar
|}
  in
  let d, _ = Conex_diff_provider.apply_diff p diff in
  Alcotest.check Alcotest.bool __LOC__
    true (d.exists ["packages" ; "foo"]) ;
  Alcotest.check Alcotest.bool __LOC__
    false (d.exists ["packages" ; "bar"]) ;
  Alcotest.check (result (Alcotest.list it) str_err) __LOC__
    (Ok [ File, "foo" ]) (d.read_dir ["packages"]) ;
  Alcotest.check (result ft str_err) __LOC__
    (Error "") (d.file_type ["packages" ; "bar"]) ;
  Alcotest.check (result ft str_err) __LOC__
    (Ok File) (d.file_type ["packages" ; "foo"]) ;
  Alcotest.check (result Alcotest.string str_err) __LOC__
    (Error "") (d.read ["packages" ; "bar"]) ;
  Alcotest.check (result Alcotest.string str_err) __LOC__
    (Ok "foobar\n") (d.read ["packages" ; "foo"])

let diff_test_complex () =
  let p = Mem.mem_provider () in
  (match p.write ["packages" ; "foo" ] "bar\n" with
   | Ok () -> ()
   | Error _ -> assert false) ;
  (match p.write ["packages" ; "foobar" ] "baz\n" with
   | Ok () -> ()
   | Error _ -> assert false) ;
  (match p.write ["packages" ; "foobarbaz" ] "foobarbaz\n" with
   | Ok () -> ()
   | Error _ -> assert false) ;
  (match p.write ["packages" ; "staying" ] "data\n" with
   | Ok () -> ()
   | Error _ -> assert false) ;
  Alcotest.check (result (Alcotest.list it) str_err) __LOC__
    (Ok [ File, "staying" ; File, "foobarbaz" ; File, "foobar" ; File, "foo" ])
    (p.read_dir ["packages"]);
  let diff = {|
--- a/packages/foo
+++ b/packages/bar
@@ -1 +1 @@
-bar
+foobar
--- a/packages/foobar
+++ /dev/null
@@ -1 +0,0 @@
-baz
--- /dev/null
+++ b/packages/baz
@@ -0,0 +1 @@
+baz
--- a/packages/foobarbaz
+++ b/packages/foobarbaz
@@ -1 +1 @@
-foobarbaz
+foobar
|}
  in
  let d, _diffs = Conex_diff_provider.apply_diff p diff in
  Alcotest.check (result (Alcotest.list it) str_err) __LOC__
    (Ok [ File, "bar" ; File, "baz" ; File, "foobarbaz" ; File, "staying" ])
    (d.read_dir ["packages"]) ;
  Alcotest.check Alcotest.bool __LOC__ false (d.exists ["packages" ; "foo"]) ;
  Alcotest.check Alcotest.bool __LOC__ false (d.exists ["packages" ; "foobar"]) ;
  Alcotest.check Alcotest.bool __LOC__ true (d.exists ["packages" ; "foobarbaz"]) ;
  Alcotest.check Alcotest.bool __LOC__ true (d.exists ["packages" ; "staying"]) ;
  Alcotest.check Alcotest.bool __LOC__ true (d.exists ["packages" ; "baz"]) ;
  Alcotest.check Alcotest.bool __LOC__ true (d.exists ["packages" ; "bar"]) ;
  Alcotest.check (result ft str_err) __LOC__ (Error "") (d.file_type ["packages" ; "foo"]) ;
  Alcotest.check (result ft str_err) __LOC__ (Error "") (d.file_type ["packages" ; "foobar"]) ;
  Alcotest.check (result ft str_err) __LOC__ (Ok File) (d.file_type ["packages" ; "foobarbaz"]) ;
  Alcotest.check (result ft str_err) __LOC__ (Ok File) (d.file_type ["packages" ; "staying"]) ;
  Alcotest.check (result ft str_err) __LOC__ (Ok File) (d.file_type ["packages" ; "baz"]) ;
  Alcotest.check (result ft str_err) __LOC__ (Ok File) (d.file_type ["packages" ; "bar"]) ;
  Alcotest.check (result Alcotest.string str_err) __LOC__ (Error "") (d.read ["packages" ; "foo"]) ;
  Alcotest.check (result Alcotest.string str_err) __LOC__ (Error "") (d.read ["packages" ; "foobar"]) ;
  Alcotest.check (result Alcotest.string str_err) __LOC__ (Ok "foobar\n") (d.read ["packages" ; "foobarbaz"]) ;
  Alcotest.check (result Alcotest.string str_err) __LOC__ (Ok "data\n") (d.read ["packages" ; "staying"]) ;
  Alcotest.check (result Alcotest.string str_err) __LOC__ (Ok "baz\n") (d.read ["packages" ; "baz"]) ;
  Alcotest.check (result Alcotest.string str_err) __LOC__ (Ok "foobar\n") (d.read ["packages" ; "bar"])

let tests = [
  "empty provider", `Quick, empty_p ;
  "basic provider", `Quick, basic_p ;
  "more provider", `Quick, more_p ;
  "diff provider create", `Quick, diff_test_create ;
  "diff provider remove", `Quick, diff_test_remove ;
  "diff provider rename", `Quick, diff_test_rename ;
  "diff provider edit", `Quick, diff_test_edit ;
  "diff provider complex", `Quick, diff_test_complex ;
]
