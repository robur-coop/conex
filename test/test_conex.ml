open Conex_utils
open Conex_resource

open Common

let wire_s str =
  let ( let* ) = Result.bind in
  match
    let* wire = Conex_opam_encoding.decode str in
    match M.find_opt "expr" wire with
    | None -> Error "couldn't find expr in wire"
    | Some wire -> Ok wire
  with
  | Ok a -> a
  | Error e -> Alcotest.fail e

module ExprTests = struct

  let expr =
    let module M = struct
      type t = Expression.t
      let pp = Expression.pp
      let equal = Expression.equal
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let basic_bad_of_wire () =
    Alcotest.check (result expr str_err) "wrong wire"
      (Error "") (Expression.of_wire (Wire.List [])) ;
    Alcotest.check (result expr str_err) "wrong wire 2"
      (Error "") (Expression.of_wire (Wire.Data "foo")) ;
    Alcotest.check (result expr str_err) "wrong pair"
      (Error "") (Expression.of_wire (Wire.Pair (Wire.List [], Wire.List []))) ;
    Alcotest.check (result expr str_err) "wrong pair 2"
      (Error "") (Expression.of_wire (Wire.Pair (Wire.Bigint Uint.zero, Wire.List []))) ;
    Alcotest.check (result expr str_err) "wrong pair 3"
      (Error "") (Expression.of_wire (Wire.Pair (Wire.Smallint 42, Wire.Data "foo"))) ;
    let keyref = Wire.(List [ Identifier "foo" ]) in
    Alcotest.check (result expr str_err) "bad keyref"
      (Error "")
      (Expression.of_wire (Wire.Pair (Wire.Smallint 42, Wire.List [ keyref ]))) ;
    let keyref = Wire.(List [ Identifier "foo" ; Data "bar" ; Bigint Uint.zero ]) in
    Alcotest.check (result expr str_err) "bad keyref 2"
      (Error "")
      (Expression.of_wire (Wire.Pair (Wire.Smallint 42, Wire.List [ keyref ])))

  let unsupported_alg () =
    let keyref = Wire.(List [ Identifier "foo" ; Data "bar=foo" ; Bigint Uint.zero ]) in
    Alcotest.check (result expr str_err) "unsupported algorithm ignored"
      (Ok (Expression.Quorum (0, Expression.KS.empty)))
      (Expression.of_wire (Wire.Pair (Wire.Smallint 0, Wire.List [ keyref ])))

  let basic_good_of_wire () =
    let wire = Wire.(Pair (Smallint 0, List [])) in
    Alcotest.check (result expr str_err) "good wire"
      (Ok (Expression.Quorum (0, Expression.KS.empty))) (Expression.of_wire wire) ;
    let kr1w = Wire.(List [ Identifier "foo" ; Data "sha256=foobar" ; Bigint Uint.zero ]) in
    let kr1 = Expression.Remote ("foo", (`SHA256, "foobar"), Uint.zero) in
    let wire = Wire.(Pair (Smallint 1, List [ kr1w ])) in
    Alcotest.check (result expr str_err) "good non-zero wire with keyref"
      (Ok (Expression.Quorum (1, Expression.KS.singleton kr1)))
      (Expression.of_wire wire) ;
    let kr2w = Wire.(List [ Identifier "bar" ; Data "sha256=barfoo" ; Bigint Uint.zero ]) in
    let kr2 = Expression.Remote ("bar", (`SHA256, "barfoo"), Uint.zero) in
    let wire = Wire.And (Wire.(Pair (Smallint 1, List [kr1w])), Wire.(Pair (Smallint 1, List [kr2w]))) in
    Alcotest.check (result expr str_err) "good non-zero wire with and"
      (Ok (Expression.And (Expression.Quorum (1, Expression.KS.singleton kr1),
                           Expression.Quorum (1, Expression.KS.singleton kr2))))
      (Expression.of_wire wire) ;
    let wire = Wire.Or (Wire.(Pair (Smallint 1, List [kr1w])), Wire.(Pair (Smallint 1, List [kr2w]))) in
    Alcotest.check (result expr str_err) "good non-zero wire with or"
      (Ok (Expression.Or (Expression.Quorum (1, Expression.KS.singleton kr1),
                          Expression.Quorum (1, Expression.KS.singleton kr2))))
      (Expression.of_wire wire) ;
    let kr3w = Wire.(List [ Identifier "foobar" ; Data "sha256=fbarfoo" ; Bigint Uint.zero ]) in
    let kr3 = Expression.Remote ("foobar", (`SHA256, "fbarfoo"), Uint.zero) in
    let wire =
      Wire.And
        (Wire.Or (Wire.(Pair (Smallint 1, List [kr1w])),
                  Wire.(Pair (Smallint 1, List [kr2w]))),
         Wire.(Pair (Smallint 1, List [kr3w])))
    in
    Alcotest.check (result expr str_err) "good non-zero wire with and and or"
      (Ok (Expression.And (Expression.Or
                             (Expression.Quorum (1, Expression.KS.singleton kr1),
                              Expression.Quorum (1, Expression.KS.singleton kr2)),
                           Expression.Quorum (1, Expression.KS.singleton kr3))))
      (Expression.of_wire wire)

  let basic_of_string () =
    let a = Expression.Quorum (1, Expression.KS.singleton (Expression.Local "a"))
    and b = Expression.Quorum (1, Expression.KS.singleton (Expression.Local "b"))
    in
    let str = "expr: (1 [ [ rootA \"sha256=abcdef\" 0x0 ] ])" in
    Alcotest.check (result expr str_err) "simple expression from string"
      (Ok (Expression.Quorum (1, Expression.KS.singleton (Expression.Remote ("rootA", (`SHA256, "abcdef"), Uint.zero)))))
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: (1 [ rootA \"sha256=abcdef\" 0x0 ])" in
    Alcotest.check (result expr str_err) "simpler expression from string"
      (Ok (Expression.Quorum (1, Expression.KS.singleton (Expression.Remote ("rootA", (`SHA256, "abcdef"), Uint.zero)))))
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: (0 [ rootA \"sha1=abcdef\" 0x0 ])" in
    Alcotest.check (result expr str_err) "simpler expression from string with unknown hash"
      (Ok (Expression.Quorum (0, Expression.KS.empty)))
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: (1 [ foo \"sha1abcdef\" 0x0 ])" in
    Alcotest.check (result expr str_err) "simpler expression from string with unknown hash"
      (Error "") (Expression.of_wire (wire_s str)) ;
    let str = "expr: ((1 [ rootA \"sha256=abcdef\" 0x0 ]) & (1 [ a ]))" in
    Alcotest.check (result expr str_err) "and expression from string"
      (Ok (Expression.And (Expression.Quorum (1, Expression.KS.singleton (Expression.Remote ("rootA", (`SHA256, "abcdef"), Uint.zero))), a)))
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: ((1 [ rootA \"sha256=abcdef\" 0x0 ]) | (1 [ a ]))" in
    Alcotest.check (result expr str_err) "or expression from string"
      (Ok (Expression.Or (Expression.Quorum (1, Expression.KS.singleton (Expression.Remote ("rootA", (`SHA256, "abcdef"), Uint.zero))), a)))
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: (1 [ a ]) & (1 [ b ])" in
    Alcotest.check (result expr str_err) "and expression from string, no paren"
      (Ok (Expression.And (a, b)))
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: (1 [ a ]) | (1 [ b ])" in
    Alcotest.check (result expr str_err) "or expression from string, no paren"
      (Ok (Expression.Or (a, b)))
      (Expression.of_wire (wire_s str)) ;
    (* TODO: bug or feature? | has higher precedence
       fixed in opam-file-format rc2 since
       https://github.com/AltGr/opam/commit/c3a78ad962e177e339774e110dc920040b8f3583 *)
    let c = Expression.Quorum (1, Expression.KS.singleton (Expression.Local "c")) in
    let str = "expr: (1 [ a ]) & (1 [ b ]) | (1 [ c ])" in
    Alcotest.check (result expr str_err) "or expression from string, no paren"
      (Ok (Expression.Or (Expression.And (a, b), c)))
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: (1 [ a ]) | (1 [ b ]) & (1 [ c ])" in
    Alcotest.check (result expr str_err) "or expression from string, no paren"
      (Ok (Expression.Or (a, Expression.And (b, c))))
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: ((1 [ a ]) & ((1 [ b ]) | (1 [ c ])))" in
    Alcotest.check (result expr str_err) "and and or expression from string"
      (Ok (Expression.And (a, Expression.Or (b, c))))
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: ((1 [ a ]) & ((1 [ b ]) & (1 [ c ])))" in
    Alcotest.check (result expr str_err) "and and and expression from string"
      (Ok (Expression.And (a, Expression.And (b, c))))
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: ((1 [ a ]) & (1 [ b ]) & (1 [ c ]))" in
    Alcotest.check (result expr str_err) "and and and expression from string no parens"
      (Ok (Expression.And (Expression.And (a, b), c)))
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: ((1 [ a ]) | (1 [ b ]) | (1 [ c ]))" in
    Alcotest.check (result expr str_err) "or and or expression from string no parens"
      (Ok (Expression.Or (Expression.Or (a, b), c)))
      (Expression.of_wire (wire_s str))

  let local_tests () =
    let str = "expr: a" in
    let a = Expression.Quorum (1, Expression.KS.singleton (Expression.Local "a")) in
    Alcotest.check (result expr str_err) "local minimal expression (a)"
      (Ok a)
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: (1 a)" in
    Alcotest.check (result expr str_err) "local tiny expression"
      (Ok (Expression.Quorum (1, Expression.KS.of_list [ Expression.Local "a" ])))
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: (1 [ a ])" in
    Alcotest.check (result expr str_err) "local small expression"
      (Ok a)
      (Expression.of_wire (wire_s str)) ;
    let str = "expr: (1 [ a b ])" in
    Alcotest.check (result expr str_err) "local simple quorum"
      (Ok (Expression.Quorum (1, Expression.KS.of_list [ Expression.Local "a" ; Expression.Local "b" ])))
      (Expression.of_wire (wire_s str))

  let compare_tests () =
    let a = Expression.KS.singleton (Expression.Local "a")
    and b = Expression.KS.singleton (Expression.Local "b")
    in
    let a_q = Expression.Quorum (1, a)
    and a_q2 = Expression.Quorum (2, a)
    and a_q3 = Expression.Quorum (1, Expression.KS.add (Expression.Local "b") a)
    and b_q = Expression.Quorum (1, b)
    in
    let a_or_b = Expression.Or (a_q, b_q)
    and a_and_b = Expression.And (a_q, b_q)
    and b_or_a = Expression.Or (b_q, a_q)
    and b_and_a = Expression.And (b_q, a_q)
    in
    Alcotest.(check bool "basic expression equality" true
                Expression.(equal a_q a_q &&
                            equal a_or_b a_or_b &&
                            equal a_and_b a_and_b));
    Alcotest.(check bool "basic expression inequality 1" false
                Expression.(equal a_q b_q));
    Alcotest.(check bool "basic expression inequality 2" false
                Expression.(equal a_q a_q2));
    Alcotest.(check bool "basic expression inequality 3" false
                Expression.(equal a_q a_or_b));
    Alcotest.(check bool "basic expression inequality 4" false
                Expression.(equal a_q a_and_b));
    Alcotest.(check bool "basic expression inequality 5" false
                Expression.(equal a_q b_or_a));
    Alcotest.(check bool "basic expression inequality 6" false
                Expression.(equal a_q b_and_a));
    Alcotest.(check bool "basic expression inequality 7" false
                Expression.(equal a_or_b b_or_a));
    Alcotest.(check bool "basic expression inequality 8" false
                Expression.(equal a_and_b b_and_a));
    Alcotest.(check bool "basic expression inequality 9" false
                Expression.(equal a_q a_q3));
    Alcotest.(check bool "basic expression inequality 10" false
                Expression.(equal a_q2 a_q3));
    Alcotest.(check int "basic expression comparison 1" 0
                Expression.(compare a_q (Quorum (1, KS.singleton (Local "a")))));
    Alcotest.(check int "basic expression comparison 2" 0
                Expression.(compare a_q2 (Quorum (2, KS.singleton (Local "a")))));
    Alcotest.(check int "basic expression comparison 3" 0
                Expression.(compare b_q (Quorum (1, KS.singleton (Local "b")))));
    Alcotest.(check int "basic expression comparison 4" 0
                Expression.(compare a_or_b (Or (Quorum (1, KS.singleton (Local "a")), Quorum (1, KS.singleton (Local "b"))))));
    Alcotest.(check int "basic expression comparison 5" 0
                Expression.(compare a_and_b (And (Quorum (1, KS.singleton (Local "a")), Quorum (1, KS.singleton (Local "b"))))));
    Alcotest.(check int "basic expression comparison not equal 1" (-1)
                Expression.(compare a_q a_q2));
    Alcotest.(check int "basic expression comparison not equal 2" 1
                Expression.(compare a_q2 a_q));
    Alcotest.(check int "basic expression comparison not equal 3" (-1)
                Expression.(compare a_and_b b_and_a));
    Alcotest.(check int "basic expression comparison not equal 4" 1
                Expression.(compare b_and_a a_and_b));
    Alcotest.(check int "basic expression comparison not equal 5" (-1)
                Expression.(compare a_and_b a_or_b));
    Alcotest.(check int "basic expression comparison not equal 6" 1
                Expression.(compare a_or_b a_and_b));
    Alcotest.(check int "basic expression comparison not equal 7" (-1)
                Expression.(compare a_and_b b_or_a));
    Alcotest.(check int "basic expression comparison not equal 8" 1
                Expression.(compare b_or_a a_and_b));
    Alcotest.(check int "basic expression comparison not equal 9" (-1)
                Expression.(compare a_or_b b_or_a));
    Alcotest.(check int "basic expression comparison not equal 10" 1
                Expression.(compare b_or_a a_or_b));
    Alcotest.(check int "basic expression comparison not equal 11" 1
                Expression.(compare a_and_b a_q));
    Alcotest.(check int "basic expression comparison not equal 12" (-1)
                Expression.(compare a_q a_and_b));
    Alcotest.(check int "basic expression comparison not equal 13" (-1)
                Expression.(compare a_q a_q3));
    Alcotest.(check int "basic expression comparison not equal 14" 1
                Expression.(compare a_q3 a_q));
    Alcotest.(check int "basic expression comparison not equal 15" (-1)
                Expression.(compare a_q3 a_q2));
    Alcotest.(check int "basic expression comparison not equal 16" 1
                Expression.(compare a_q2 a_q3))

  let keys_tests () =
    let a = Expression.KS.singleton (Expression.Local "a")
    and b = Expression.KS.singleton (Expression.Local "b")
    in
    let a_q = Expression.Quorum (1, a)
    and b_q = Expression.Quorum (1, b)
    in
    let a_or_b = Expression.Or (a_q, b_q)
    and a_and_b = Expression.And (a_q, b_q)
    in
    Alcotest.(check int "keys size of map a_q" 0
                (M.cardinal (Expression.keys M.empty a_q)));
    Alcotest.(check int "keys size of map b_q" 0
                (M.cardinal (Expression.keys M.empty b_q)));
    Alcotest.(check int "keys size of map a_or_b" 0
                (M.cardinal (Expression.keys M.empty a_or_b)));
    Alcotest.(check int "keys size of map a_and_b" 0
                (M.cardinal (Expression.keys M.empty a_and_b)));
    let ar = Expression.KS.singleton (Expression.Remote ("a", (`SHA256, "abcdef"), Uint.zero))
    and br = Expression.KS.singleton (Expression.Remote ("b", (`SHA256, "abcdef"), Uint.zero))
    in
    let ar_q = Expression.Quorum (1, ar)
    and br_q = Expression.Quorum (1, br)
    in
    let ar_or_br = Expression.Or (ar_q, br_q)
    and ar_and_br = Expression.And (ar_q, br_q)
    in
    let a_ar_q = Expression.Quorum (1, Expression.KS.union a ar)
    and b_br_q = Expression.Quorum (1, Expression.KS.union b br)
    in
    Alcotest.(check int "keys size of map ar_q" 1
                (M.cardinal (Expression.keys M.empty ar_q)));
    Alcotest.(check int "keys size of map br_q" 1
                (M.cardinal (Expression.keys M.empty br_q)));
    Alcotest.(check int "keys size of map a_ar_q" 1
                (M.cardinal (Expression.keys M.empty a_ar_q)));
    Alcotest.(check int "keys size of map b_br_q" 1
                (M.cardinal (Expression.keys M.empty b_br_q)));
    Alcotest.(check int "keys size of map ar_or_br" 2
                (M.cardinal (Expression.keys M.empty ar_or_br)));
    Alcotest.(check int "keys size of map ar_and_br" 2
                (M.cardinal (Expression.keys M.empty ar_and_br)));
    let ar' = Expression.KS.singleton (Expression.Remote ("a", (`SHA256, "abcdef"), Uint.zero)) in
    let ar'_q = Expression.Quorum (1, ar') in
    let ar_and_ar' = Expression.And (ar_q, ar'_q) in
    Alcotest.(check int "keys size of map ar_and_ar' 1" 1
                (M.cardinal (Expression.keys M.empty ar_and_ar')));
    let ar' = Expression.KS.singleton (Expression.Remote ("a", (`SHA256, "abcde"), Uint.zero)) in
    let ar'_q = Expression.Quorum (1, ar') in
    let ar_and_ar' = Expression.And (ar_q, ar'_q) in
    Alcotest.(check int "keys size of map ar_and_ar' 2" 1
                (M.cardinal (Expression.keys M.empty ar_and_ar')));
    let ar' = Expression.KS.singleton (Expression.Remote ("a", (`SHA256, "123456"), snd (Uint.succ Uint.zero))) in
    let ar'_q = Expression.Quorum (1, ar') in
    let ar_and_ar' = Expression.And (ar_q, ar'_q) in
    Alcotest.(check int "keys size of map ar_and_ar' 3" 1
                (M.cardinal (Expression.keys M.empty ar_and_ar')));
    let _, data = M.choose (Expression.keys M.empty ar_and_ar') in
    let hash, epoch = match data with
      | (`SHA256, h), e -> h, e
    in
    Alcotest.(check string "hash is the new one" "123456" hash);
    Alcotest.(check string "epoch is the new one" "0x1" (Uint.to_string epoch))

  let local_keys_tests () =
    let a = Expression.Quorum (1, Expression.KS.singleton (Expression.Local "a")) in
    let b = Expression.Quorum (1, Expression.KS.singleton (Expression.Local "b")) in
    let ab = Expression.Quorum (1, Expression.KS.of_list [ Expression.Local "a" ; Expression.Local "b" ]) in
    let a_and_b = Expression.And (a, b) in
    let a_or_b = Expression.Or (a, b) in
    Alcotest.(check (list string) "local keys of a is good" ["a"]
                (S.elements (Expression.local_keys a)));
    Alcotest.(check (list string) "local keys of b is good" ["b"]
                (S.elements (Expression.local_keys b)));
    Alcotest.(check (list string) "local keys of ab is good" ["a" ; "b"]
                (S.elements (Expression.local_keys ab)));
    Alcotest.(check (list string) "local keys of a and b is good" ["a" ; "b"]
                (S.elements (Expression.local_keys a_and_b)));
    Alcotest.(check (list string) "local keys of a or b is good" ["a" ; "b"]
                (S.elements (Expression.local_keys a_or_b)));
    let ar = Expression.Quorum (1, Expression.KS.singleton (Expression.Remote ("a", (`SHA256, "abcdef"), Uint.zero))) in
    let ar_and_b = Expression.And (ar, b) in
    let ar_or_b = Expression.Or (ar, b) in
    Alcotest.(check (list string) "local keys of ar and b is good" ["b"]
                (S.elements (Expression.local_keys ar_and_b)));
    Alcotest.(check (list string) "local keys of ar or b is good" ["b"]
                (S.elements (Expression.local_keys ar_or_b)))

  let basic_eval_tests () =
    let str = "expr: (0 [])" in
    (match Expression.of_wire (wire_s str) with
     | Error e -> Alcotest.fail e
     | Ok expr ->
       Alcotest.check Alcotest.bool "simplest expression"
         true (Expression.eval expr Digest_map.empty S.empty)) ;
    let str = "expr: a" in
    (match Expression.of_wire (wire_s str) with
     | Error e -> Alcotest.fail e
     | Ok expr ->
       Alcotest.check Alcotest.bool "simplest false expression"
         false (Expression.eval expr Digest_map.empty S.empty)) ;
    let str = "expr: (1 [ a ]) | (0 [])" in
    (match Expression.of_wire (wire_s str) with
     | Error e -> Alcotest.fail e
     | Ok expr ->
       Alcotest.check Alcotest.bool "simple or expression"
         true (Expression.eval expr Digest_map.empty S.empty)) ;
    let str = "expr: (0 []) | (1 [ a ])" in
    (match Expression.of_wire (wire_s str) with
     | Error e -> Alcotest.fail e
     | Ok expr ->
       Alcotest.check Alcotest.bool "simple or expression"
         true (Expression.eval expr Digest_map.empty S.empty)) ;
    let str = "expr: (1 [ a ]) & (1 [ b ])" in
    (match Expression.of_wire (wire_s str) with
     | Error e -> Alcotest.fail e
     | Ok expr ->
       Alcotest.check Alcotest.bool "simple and expression"
         false (Expression.eval expr Digest_map.empty S.empty)) ;
    let str = "expr: (0 []) & (0 [])" in
    (match Expression.of_wire (wire_s str) with
     | Error e -> Alcotest.fail e
     | Ok expr ->
       Alcotest.check Alcotest.bool "simple and expression with two times zero"
         true (Expression.eval expr Digest_map.empty S.empty))

  let eval_test_1 () =
    let str = "expr: (1 [ rootA \"sha256=abcdef\" 0x0 ])" in
    match Expression.of_wire (wire_s str) with
    | Error e -> Alcotest.fail e
    | Ok expr ->
      let dm = Digest_map.add (`SHA256, "abcdef") ("rootA", Uint.zero) Digest_map.empty in
      Alcotest.check Alcotest.bool "simple true expression"
        true (Expression.eval expr dm S.empty) ;
      let dm = Digest_map.add (`SHA256, "abcdefg") ("rootA", Uint.zero) Digest_map.empty in
      Alcotest.check Alcotest.bool "simple true expression is wrong (wrong hash)"
        false (Expression.eval expr dm S.empty) ;
      let dm = Digest_map.add (`SHA256, "abcdef") ("rootB", Uint.zero) Digest_map.empty in
      Alcotest.check Alcotest.bool "simple true expression is wrong (wrong id)"
        false (Expression.eval expr dm S.empty)

  let eval_test_2 () =
    let str = "expr: (1 [ [ rootA \"sha256=abcdef\" 0x0 ] [ rootB \"sha1=foo\" 0x0 ] ])" in
    match Expression.of_wire (wire_s str) with
    | Error e -> Alcotest.fail e
    | Ok expr ->
      let dm = Digest_map.add (`SHA256, "abcdef") ("rootA", Uint.zero) Digest_map.empty in
      Alcotest.check Alcotest.bool "simple true expression with unknown hash"
        true (Expression.eval expr dm S.empty) ;
      let dm = Digest_map.add (`SHA256, "abcdefg") ("rootA", Uint.zero) Digest_map.empty in
      Alcotest.check Alcotest.bool "simple true expression with unknown hash is wrong (wrong hash)"
        false (Expression.eval expr dm S.empty) ;
      let dm = Digest_map.add (`SHA256, "abcdef") ("rootB", Uint.zero) Digest_map.empty in
      Alcotest.check Alcotest.bool "simple true expression with unknown hash is wrong (wrong id)"
        false (Expression.eval expr dm S.empty)

  let eval_test_3 () =
    let str = "expr: (1 [ [ rootA \"sha256=abcdef\" 0x0 ] [ rootB \"sha256=foobar\" 0x0 ] ])" in
    let str' = "expr: (2 [ [ rootA \"sha256=abcdef\" 0x0 ] [ rootB \"sha256=foobar\" 0x0 ] ])" in
    match Expression.of_wire (wire_s str), Expression.of_wire (wire_s str') with
    | Error e, _ -> Alcotest.fail e
    | _, Error e -> Alcotest.fail e
    | Ok expr, Ok expr' ->
      let dm = Digest_map.empty in
      Alcotest.check Alcotest.bool "simple true expression with choice, empty dm"
        false (Expression.eval expr dm S.empty) ;
      Alcotest.check Alcotest.bool "simple true expression with quorum, empty dm"
        false (Expression.eval expr' dm S.empty) ;
      let dm = Digest_map.add (`SHA256, "abcdef") ("rootA", Uint.zero) Digest_map.empty in
      Alcotest.check Alcotest.bool "simple true expression with choice"
        true (Expression.eval expr dm S.empty) ;
      Alcotest.check Alcotest.bool "simple true expression with quorum"
        false (Expression.eval expr' dm S.empty) ;
      let dm = Digest_map.add (`SHA256, "foobar") ("rootB", Uint.zero) Digest_map.empty in
      Alcotest.check Alcotest.bool "simple true expression with choice rootB"
        true (Expression.eval expr dm S.empty) ;
      Alcotest.check Alcotest.bool "simple true expression with quorum"
        false (Expression.eval expr' dm S.empty) ;
      let dm = Digest_map.add (`SHA256, "foobar") ("rootA", Uint.zero) Digest_map.empty in
      Alcotest.check Alcotest.bool "simple true expression with wrong hash"
        false (Expression.eval expr dm S.empty) ;
      let dm =
        Digest_map.add (`SHA256, "foobar") ("rootA", Uint.zero)
          (Digest_map.add (`SHA256, "abcdef") ("rootB", Uint.zero) Digest_map.empty)
      in
      Alcotest.check Alcotest.bool "simple true expression with wrong hashes"
        false (Expression.eval expr dm S.empty) ;
      let dm =
        Digest_map.add (`SHA256, "foobar") ("rootB", Uint.zero)
          (Digest_map.add (`SHA256, "abcdefg") ("rootA", Uint.zero) Digest_map.empty)
      in
      Alcotest.check Alcotest.bool "simple true expression with one right hash and wrong hash"
        true (Expression.eval expr dm S.empty) ;
      Alcotest.check Alcotest.bool "simple true expression with one right hash and quorum"
        false (Expression.eval expr' dm S.empty) ;
      let dm =
        Digest_map.add (`SHA256, "foobar") ("rootB", Uint.zero)
          (Digest_map.add (`SHA256, "abcdef") ("rootA", Uint.zero) Digest_map.empty)
      in
      Alcotest.check Alcotest.bool "simple true expression with two right hashes"
        true (Expression.eval expr dm S.empty) ;
      Alcotest.check Alcotest.bool "simple true expression with two right hashes"
        true (Expression.eval expr dm S.empty)

  let eval_test_4 () =
    let str = "expr: (1 [ rootA \"sha256=abcdef\" 0x0 ]) & (1 [ rootB \"sha256=foobar\" 0x0 ])" in
    let str' = "expr: (1 [ rootA \"sha256=abcdef\" 0x0 ]) | (1 [ rootB \"sha256=foobar\" 0x0 ])" in
    match Expression.of_wire (wire_s str), Expression.of_wire (wire_s str') with
    | Error e, _ -> Alcotest.fail e
    | _, Error e -> Alcotest.fail e
    | Ok expr, Ok expr' ->
      let dm = Digest_map.empty in
      Alcotest.check Alcotest.bool "and expression with both quorum, empty dm"
        false (Expression.eval expr dm S.empty) ;
      Alcotest.check Alcotest.bool "or expression with both quorum, empty dm"
        false (Expression.eval expr' dm S.empty) ;
      let dm = Digest_map.add (`SHA256, "abcdef") ("rootA", Uint.zero) Digest_map.empty in
      Alcotest.check Alcotest.bool "and expression with both quorum, single in dm"
        false (Expression.eval expr dm S.empty) ;
      Alcotest.check Alcotest.bool "or expression with both quorum, single in dm"
        true (Expression.eval expr' dm S.empty) ;
      let dm = Digest_map.add (`SHA256, "foobar") ("rootB", Uint.zero) Digest_map.empty in
      Alcotest.check Alcotest.bool "and expression with both quorum, other single in dm"
        false (Expression.eval expr dm S.empty) ;
      Alcotest.check Alcotest.bool "or expression with both quorum, other single in dm"
        true (Expression.eval expr' dm S.empty) ;
      let dm =
        Digest_map.add (`SHA256, "foobar") ("rootA", Uint.zero)
          (Digest_map.add (`SHA256, "abcdef") ("rootB", Uint.zero) Digest_map.empty)
      in
      Alcotest.check Alcotest.bool "and expression with both quorum, wrong hashes in dm"
        false (Expression.eval expr dm S.empty) ;
      Alcotest.check Alcotest.bool "or expression with both quorum, wrong hashes in dm"
        false (Expression.eval expr' dm S.empty) ;
      let dm =
        Digest_map.add (`SHA256, "foobar") ("rootB", Uint.zero)
          (Digest_map.add (`SHA256, "abcdefg") ("rootA", Uint.zero) Digest_map.empty)
      in
      Alcotest.check Alcotest.bool "and expression with both quorum, one right hash and wrong hash in dm"
        false (Expression.eval expr dm S.empty) ;
      Alcotest.check Alcotest.bool "or expression with both quorum, one right hash and wrong hash in dm"
        true (Expression.eval expr' dm S.empty) ;
      let dm =
        Digest_map.add (`SHA256, "foobar") ("rootB", Uint.zero)
          (Digest_map.add (`SHA256, "abcdef") ("rootA", Uint.zero) Digest_map.empty)
      in
      Alcotest.check Alcotest.bool "and expression with both quorum, both in dm"
        true (Expression.eval expr dm S.empty) ;
      Alcotest.check Alcotest.bool "or  expression with both quorum, both in dm"
        true (Expression.eval expr dm S.empty)

  let local_eval_test_1 () =
    let str = "expr: (1 [ rootA ])" in
    match Expression.of_wire (wire_s str) with
    | Error e -> Alcotest.fail e
    | Ok expr ->
      Alcotest.check Alcotest.bool "simple true expression"
        true (Expression.eval expr Digest_map.empty (S.singleton "rootA")) ;
      Alcotest.check Alcotest.bool "simple true expression is wrong (id not signed)"
        false (Expression.eval expr Digest_map.empty S.empty)

  let local_eval_test_2 () =
    let str = "expr: (1 [ rootA rootB ])" in
    match Expression.of_wire (wire_s str) with
    | Error e -> Alcotest.fail e
    | Ok expr ->
      Alcotest.check Alcotest.bool "simple true expression where rootA signed"
        true (Expression.eval expr Digest_map.empty (S.singleton "rootA")) ;
      Alcotest.check Alcotest.bool "simple true expression where rootB signed"
        true (Expression.eval expr Digest_map.empty (S.singleton "rootB")) ;
      Alcotest.check Alcotest.bool "simple true expression where both signed"
        true (Expression.eval expr Digest_map.empty
                (S.add "rootA" (S.singleton "rootB"))) ;
      Alcotest.check Alcotest.bool "simple true expression where nobody signed"
        false (Expression.eval expr Digest_map.empty S.empty) ;
      Alcotest.check Alcotest.bool "simple true expression where nobody known signed"
        false (Expression.eval expr Digest_map.empty (S.singleton "root"))

  let local_eval_test_3 () =
    let str = "expr: (1 [ rootA rootB ])" in
    let str' = "expr: (2 [ rootA rootB ])" in
    match Expression.of_wire (wire_s str), Expression.of_wire (wire_s str') with
    | Error e, _ -> Alcotest.fail e
    | _, Error e -> Alcotest.fail e
    | Ok expr, Ok expr' ->
      let s = S.empty in
      Alcotest.check Alcotest.bool "simple true expression with choice, empty s"
        false (Expression.eval expr Digest_map.empty s) ;
      Alcotest.check Alcotest.bool "simple true expression with quorum, empty s"
        false (Expression.eval expr' Digest_map.empty s) ;
      let s = S.singleton "rootA" in
      Alcotest.check Alcotest.bool "simple true expression with choice rootA"
        true (Expression.eval expr Digest_map.empty s) ;
      Alcotest.check Alcotest.bool "simple true expression with quorum"
        false (Expression.eval expr' Digest_map.empty s) ;
      let s = S.singleton "rootB" in
      Alcotest.check Alcotest.bool "simple true expression with choice rootB"
        true (Expression.eval expr Digest_map.empty s) ;
      Alcotest.check Alcotest.bool "simple true expression with quorum"
        false (Expression.eval expr' Digest_map.empty s) ;
      let s = S.add "rootA" (S.singleton "rootB") in
      Alcotest.check Alcotest.bool "simple true expression with choice rootA rootB"
        true (Expression.eval expr Digest_map.empty s) ;
      Alcotest.check Alcotest.bool "simple true expression with quorum"
        true (Expression.eval expr' Digest_map.empty s)

  let local_eval_test_4 () =
    let str = "expr: rootA & rootB" in
    let str' = "expr: rootA | rootB" in
    match Expression.of_wire (wire_s str), Expression.of_wire (wire_s str') with
    | Error e, _ -> Alcotest.fail e
    | _, Error e -> Alcotest.fail e
    | Ok expr, Ok expr' ->
      let dm = Digest_map.empty in
      let s = S.empty in
      Alcotest.check Alcotest.bool "and expression with both quorum, empty s"
        false (Expression.eval expr dm s) ;
      Alcotest.check Alcotest.bool "or expression with both quorum, empty s"
        false (Expression.eval expr' dm s) ;
      let s = S.singleton "rootA" in
      Alcotest.check Alcotest.bool "and expression with both quorum, single in s"
        false (Expression.eval expr dm s) ;
      Alcotest.check Alcotest.bool "or expression with both quorum, single in s"
        true (Expression.eval expr' dm s) ;
      let s = S.singleton "rootB" in
      Alcotest.check Alcotest.bool "and expression with both quorum, other single in s"
        false (Expression.eval expr dm s) ;
      Alcotest.check Alcotest.bool "or expression with both quorum, other single in s"
        true (Expression.eval expr' dm s) ;
      let s = S.add "rootA" (S.singleton "rootB") in
      Alcotest.check Alcotest.bool "and expression with both quorum, both in s"
        true (Expression.eval expr dm s) ;
      Alcotest.check Alcotest.bool "or expression with both quorum, both in s"
        true (Expression.eval expr' dm s)

  let roundtrip str exp () =
    Alcotest.check (result expr str_err) "simple expression from string"
      (Ok exp)
      (Expression.of_wire (wire_s str)) ;
    let exp = match Expression.of_wire (wire_s str) with
      | Ok e -> e
      | _ -> Alcotest.fail "unexpected"
    in
    Alcotest.check (result expr str_err) "simple expression from wire"
      (Ok exp) (Expression.of_wire (Expression.to_wire exp))

  let of_string_to_wire_of_wire () =
    let str = "expr: (1 [ [ rootA \"sha256=abcdef\" 0x0 ] ])"
    and expr = Expression.Quorum (1, Expression.KS.singleton (Expression.Remote ("rootA", (`SHA256, "abcdef"), Uint.zero)))
    in
    roundtrip str expr () ;
    let str = "expr: (1 [ [ rootA \"sha256=abcdef\" 0x0 ] ]) & (0 [ ])"
    and expr = Expression.And
        (Expression.Quorum (1, Expression.KS.singleton (Expression.Remote ("rootA", (`SHA256, "abcdef"), Uint.zero))),
         Expression.Quorum (0, Expression.KS.empty))
    in
    roundtrip str expr () ;
    let str = "expr: (1 [ [ rootA \"sha256=abcdef\" 0x0 ] ]) | (0 [ ])"
    and expr = Expression.Or
        (Expression.Quorum (1, Expression.KS.singleton (Expression.Remote ("rootA", (`SHA256, "abcdef"), Uint.zero))),
         Expression.Quorum (0, Expression.KS.empty))
    in
    roundtrip str expr ()

  let tests = [
    "basic bad of_wire", `Quick, basic_bad_of_wire ;
    "unsupported algorithm", `Quick, unsupported_alg ;
    "basic good of_wire", `Quick, basic_good_of_wire ;
    "basic of_string", `Quick, basic_of_string ;
    "local tests", `Quick, local_tests ;
    "compare tests", `Quick, compare_tests ;
    "keys tests", `Quick, keys_tests ;
    "local keys tests", `Quick, local_keys_tests ;
    "basic eval", `Quick, basic_eval_tests ;
    "eval test 1", `Quick, eval_test_1 ;
    "eval test 2", `Quick, eval_test_2 ;
    "eval test 3", `Quick, eval_test_3 ;
    "eval test 4", `Quick, eval_test_4 ;
    "local eval test 1", `Quick, local_eval_test_1 ;
    "local eval test 2", `Quick, local_eval_test_2 ;
    "local eval test 3", `Quick, local_eval_test_3 ;
    "local eval test 4", `Quick, local_eval_test_4 ;
    "of_string to_wire of_wire", `Quick, of_string_to_wire_of_wire ;
  ]
end

module KeyTests = struct
  let key =
    let module M = struct
      type t = Key.t
      let pp = Key.pp
      let equal = Key.equal
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let basic_bad_of_wire () =
    Alcotest.check (result key r_err) "wrong wire"
      (Error `Malformed) (Key.of_wire (Wire.List [])) ;
    Alcotest.check (result key r_err) "wrong wire 2"
      (Error (`Parse "")) (Key.of_wire (Wire.Data "")) ;
    Alcotest.check (result key r_err) "wrong wire 3"
      (Error `Malformed) (Key.of_wire (Wire.List [ Wire.Data "foo" ])) ;
    Alcotest.check (result key r_err) "wrong wire 4"
      (Error `Malformed) (Key.of_wire (Wire.List [ Wire.Identifier "foo" ; Wire.Data "ts" ; Wire.Data "key" ])) ;
    Alcotest.check (result key r_err) "wrong wire 5"
      (Error (`Unknown_alg "")) (Key.of_wire (Wire.List [ Wire.Identifier "foo" ; Wire.Data "ts" ; Wire.Data "dsa=key" ]))

  let good_of_wire () =
    Alcotest.check (result key r_err) "good wire 1"
      (Ok ("foo", "ts", `RSA, "key"))
      (Key.of_wire (Wire.List [ Wire.Identifier "foo" ; Wire.Data "ts" ; Wire.Data "rsa=key" ]))

  let basic_of_string () =
    let str = "expr: [ foo \"timestamp\" \"rsa=abc\" ]" in
    Alcotest.check (result key r_err) "basic good key"
      (Ok ("foo", "timestamp", `RSA, "abc"))
      (Key.of_wire (wire_s str)) ;
    let str = "expr: [ foobar ]" in
    Alcotest.check (result key r_err) "basic bad key 1"
      (Error `Malformed)
      (Key.of_wire (wire_s str)) ;
    let str = "expr: [ foobar \"timestamp\" \"foo\" ]" in
    Alcotest.check (result key r_err) "basic bad key 2"
      (Error `Malformed)
      (Key.of_wire (wire_s str)) ;
    let str = "expr: [ foobar timestamp \"rsa=foo\" ]" in
    Alcotest.check (result key r_err) "basic bad key 2"
      (Error `Malformed)
      (Key.of_wire (wire_s str)) ;
    let str = "expr: [ foobar \"timestamp\" \"dsa=foo\" ]" in
    Alcotest.check (result key r_err) "basic unknown alg"
      (Error (`Unknown_alg ""))
      (Key.of_wire (wire_s str))

  let key_of_string_to_wire_of_wire () =
    let str = "expr: [ foo \"timestamp\" \"rsa=abc\" ]" in
    Alcotest.check (result key r_err) "basic good key"
      (Ok ("foo", "timestamp", `RSA, "abc"))
      (Key.of_wire (wire_s str)) ;
    let mkey = match Key.of_wire (wire_s str) with
      | Ok key -> key | _ -> Alcotest.fail "unexpected"
    in
    Alcotest.check (result key r_err) "basic good key"
      (Ok mkey) (Key.of_wire (Key.wire_raw mkey))

  let tests = [
    "bad of_wire", `Quick, basic_bad_of_wire ;
    "good of_wire", `Quick, good_of_wire ;
    "basic of_string", `Quick, basic_of_string ;
    "of_string to_wire of_wire", `Quick, key_of_string_to_wire_of_wire ;
  ]
end

module SigTests = struct

  let zig =
    let module M = struct
      type t = Signature.t
      let pp = Signature.pp
      let equal = Signature.equal
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let basic_bad_of_wire () =
    Alcotest.check (result zig r_err) "wrong wire"
      (Error `Malformed) (Signature.of_wire (Wire.List [])) ;
    Alcotest.check (result zig r_err) "wrong wire 2"
      (Error (`Parse "")) (Signature.of_wire (Wire.Data "foo")) ;
    Alcotest.check (result zig r_err) "wrong wire 3"
      (Error (`Parse "")) (Signature.of_wire (Wire.Identifier "bar")) ;
    Alcotest.check (result zig r_err) "wrong wire 4"
      (Error `Malformed) (Signature.of_wire (Wire.List [ Wire.Identifier "bar" ; Wire.Data "now" ; Wire.Data "foobar" ])) ;
    Alcotest.check (result zig r_err) "unknown alg"
      (Error (`Unknown_alg ""))
      (Signature.of_wire (Wire.List [ Wire.Identifier "foo" ; Wire.Data "now" ; Wire.Data "rsapsssha256=foobar"]))

  let basic_good_of_wire () =
    Alcotest.check (result zig r_err) "good wire"
      (Ok ("foo", "now", `RSA_PSS_SHA256, "foobar"))
      (Signature.of_wire (Wire.List [ Wire.Identifier "foo" ; Wire.Data "now" ; Wire.Data "rsapss-sha256=foobar"]))

  let basic_of_string () =
    let str = "expr: [ foo \"timestamp\" \"rsapss-sha256=abc\" ]" in
    Alcotest.check (result zig r_err) "basic good signature"
      (Ok ("foo", "timestamp", `RSA_PSS_SHA256, "abc"))
      (Signature.of_wire (wire_s str)) ;
    let str = "expr: [ foobar ]" in
    Alcotest.check (result zig r_err) "basic bad signature 1"
      (Error `Malformed)
      (Signature.of_wire (wire_s str)) ;
    let str = "expr: [ foobar \"timestamp\" \"foo\" ]" in
    Alcotest.check (result zig r_err) "basic bad signature 2"
      (Error `Malformed)
      (Signature.of_wire (wire_s str)) ;
    let str = "expr: [ foobar timestamp \"rsa=foo\" ]" in
    Alcotest.check (result zig r_err) "basic bad signature 2"
      (Error `Malformed)
      (Signature.of_wire (wire_s str)) ;
    let str = "expr: [ foobar \"timestamp\" \"dsa=foo\" ]" in
    Alcotest.check (result zig r_err) "basic unknown alg"
      (Error (`Unknown_alg ""))
      (Signature.of_wire (wire_s str))

  let of_string_to_wire_of_wire () =
    let str = "expr: [ foo \"timestamp\" \"rsapss-sha256=abc\" ]" in
    Alcotest.check (result zig r_err) "basic good signature"
      (Ok ("foo", "timestamp", `RSA_PSS_SHA256, "abc"))
      (Signature.of_wire (wire_s str)) ;
    let msig = match Signature.of_wire (wire_s str) with
      | Ok signature -> signature | _ -> Alcotest.fail "unexpected"
    in
    Alcotest.check (result zig r_err) "basic good signature"
      (Ok msig) (Signature.of_wire (Signature.wire_raw msig))

  let tests = [
    "bad of_wire", `Quick, basic_bad_of_wire ;
    "good of_wire", `Quick, basic_good_of_wire ;
    "basic of_string", `Quick, basic_of_string ;
    "of_string to_wire of_wire", `Quick, of_string_to_wire_of_wire ;
  ]
end

module DigestTests = struct
  let dig =
    let module M = struct
      type t = Digest.t
      let pp = Digest.pp
      let equal = Digest.equal
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let basic_bad_of_wire () =
    Alcotest.check (result dig r_err) "wrong wire"
      (Error `Malformed) (Digest.of_wire (Wire.List [])) ;
    Alcotest.check (result dig r_err) "wrong wire 2"
      (Error `Malformed) (Digest.of_wire (Wire.Data "foo")) ;
    Alcotest.check (result dig r_err) "wrong wire 3"
      (Error `Malformed) (Digest.of_wire (Wire.Identifier "bar")) ;
    Alcotest.check (result dig r_err) "wrong wire 3.5"
      (Error `Malformed) (Digest.of_wire (Wire.Identifier "bar=foo")) ;
    Alcotest.check (result dig r_err) "wrong wire 4"
      (Error `Malformed) (Digest.of_wire (Wire.List [ Wire.Identifier "bar" ; Wire.Data "now" ; Wire.Data "foobar" ])) ;
    Alcotest.check (result dig r_err) "unknown alg"
      (Error (`Unknown_alg ""))
      (Digest.of_wire (Wire.Data "now=foofoffo"))

  let basic_good_of_wire () =
    Alcotest.check (result dig r_err) "good wire"
      (Ok (`SHA256, "now"))
      (Digest.of_wire (Wire.Data "sha256=now"))

  let basic_of_string () =
    let str = "expr: \"sha256=foo\"" in
    Alcotest.check (result dig r_err) "basic good digest"
      (Ok (`SHA256, "foo"))
      (Digest.of_wire (wire_s str)) ;
    let str = "expr: [ foobar ]" in
    Alcotest.check (result dig r_err) "basic bad digest 1"
      (Error `Malformed)
      (Digest.of_wire (wire_s str)) ;
    let str = "expr: [ foobar \"timestamp\" \"foo\" ]" in
    Alcotest.check (result dig r_err) "basic bad digest 2"
      (Error `Malformed)
      (Digest.of_wire (wire_s str)) ;
    let str = "expr: [ foobar timestamp \"rsa=foo\" ]" in
    Alcotest.check (result dig r_err) "basic bad digest 2"
      (Error `Malformed)
      (Digest.of_wire (wire_s str)) ;
    let str = "expr: \"sha1=abc\"" in
    Alcotest.check (result dig r_err) "basic unknown alg"
      (Error (`Unknown_alg ""))
      (Digest.of_wire (wire_s str))

  let of_string_to_wire_of_wire () =
    let str = "expr: \"sha256=abc\"" in
    Alcotest.check (result dig r_err) "basic good digest"
      (Ok (`SHA256, "abc"))
      (Digest.of_wire (wire_s str)) ;
    let mdgst = match Digest.of_wire (wire_s str) with
      | Ok dgst -> dgst | _ -> Alcotest.fail "unexpected"
    in
    Alcotest.check (result dig r_err) "basic good digest"
      (Ok mdgst) (Digest.of_wire (Digest.wire_raw mdgst))

  let tests = [
    "bad of_wire", `Quick, basic_bad_of_wire ;
    "good of_wire", `Quick, basic_good_of_wire ;
    "basic of_string", `Quick, basic_of_string ;
    "of_string to_wire of_wire", `Quick, of_string_to_wire_of_wire ;
  ]
end

module RootTests = struct

  let roo =
    let module M = struct
      type t = Root.t * string list
      let pp ppf (r, _) = Root.pp ppf r
      let equal (r, _) (r', _) =
        Uint.compare r.Root.counter r'.Root.counter = 0 &&
        Uint.compare r.Root.epoch r'.Root.epoch = 0 &&
        id_equal r.Root.name r'.Root.name &&
        path_equal r.Root.datadir r'.Root.datadir &&
        path_equal r.Root.keydir r'.Root.keydir &&
        Root.RM.equal Expression.equal r.Root.roles r'.Root.roles &&
        M.equal Signature.equal r.Root.signatures r'.Root.signatures
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let basic_bad_of_wire () =
    Alcotest.check (result roo str_err) "wrong wire"
      (Error "") (Root.of_wire (M.add "foo" (Wire.List []) M.empty)) ;
    Alcotest.check (result roo str_err) "wrong wire 2"
      (Error "") (Root.of_wire (M.add "bar" (Wire.Data "foo") M.empty)) ;
    Alcotest.check (result roo str_err) "wrong wire 3"
      (Error "") (Root.of_wire (M.add "name" (Wire.Identifier "bar") M.empty)) ;
    Alcotest.check (result roo str_err) "wrong wire 3.5"
      (Error "") (Root.of_wire (M.add "name" (Wire.Identifier "bar=foo") M.empty))

  let empty_valid = Expression.Quorum (0, Expression.KS.empty)

  let basic_good_of_wire () =
    let signed =
      M.add "version" (Wire.Smallint 1)
        (M.add "created" (Wire.Data "now")
           (M.add "counter" (Wire.Bigint Uint.zero)
              (M.add "epoch" (Wire.Bigint Uint.zero)
                 (M.add "name" (Wire.Data "root")
                    (M.add "typ" (Wire.Identifier "root")
                       (M.add "datadir" (Wire.Data "/here")
                          (M.add "keydir" (Wire.Data "/there")
                             (M.add "valid" (Wire.Pair (Wire.Smallint 0, Wire.List []))
                                (M.add "keys" (Wire.List [])
                                   (M.add "roles" (Wire.Map M.empty) M.empty))))))))))
    in
    let root_wire s =
      M.add "signed" (Wire.Map s) (M.add "signatures" (Wire.List []) M.empty)
    in
    let root = { Root.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
                 name = "root" ; datadir = [ "here" ] ; keydir = [ "there" ] ;
                 keys = M.empty ; roles = Root.RM.empty ; signatures = M.empty ; valid = empty_valid }
    in
    Alcotest.check (result roo str_err) "good wire"
      (Ok (root, [])) (Root.of_wire (root_wire signed)) ;
    let bad_version = root_wire (M.add "version" (Wire.Smallint 42) signed) in
    Alcotest.check (result roo str_err) "bad version (42) in wire"
      (Error "") (Root.of_wire bad_version) ;
    let bad_version = root_wire (M.add "version" (Wire.Data "1") signed) in
    Alcotest.check (result roo str_err) "bad version (string) in wire"
      (Error "") (Root.of_wire bad_version) ;
    let bad_counter = root_wire (M.add "counter" (Wire.Smallint 23) signed) in
    Alcotest.check (result roo str_err) "bad counter (smallint) in wire"
      (Error "") (Root.of_wire bad_counter) ;
    let bad_counter = root_wire (M.add "counter" (Wire.Data "42") signed) in
    Alcotest.check (result roo str_err) "bad counter (string) in wire"
      (Error "") (Root.of_wire bad_counter) ;
    let bad_epoch = root_wire (M.add "epoch" (Wire.Smallint 23) signed) in
    Alcotest.check (result roo str_err) "bad epoch (smallint) in wire"
      (Error "") (Root.of_wire bad_epoch) ;
    let bad_epoch = root_wire (M.add "epoch" (Wire.Data "42") signed) in
    Alcotest.check (result roo str_err) "bad epoch (string) in wire"
      (Error "") (Root.of_wire bad_epoch) ;
    let bad_typ = root_wire (M.add "typ" (Wire.Identifier "key") signed) in
    Alcotest.check (result roo str_err) "bad typ (key) in wire"
      (Error "") (Root.of_wire bad_typ) ;
    let bad_typ = root_wire (M.add "typ" (Wire.Identifier "keyfoo") signed) in
    Alcotest.check (result roo str_err) "bad typ (keyfoo) in wire"
      (Error "") (Root.of_wire bad_typ) ;
    let bad_typ = root_wire (M.add "typ" (Wire.Data "root") signed) in
    Alcotest.check (result roo str_err) "bad typ (string root) in wire"
      (Error "") (Root.of_wire bad_typ) ;
    let bad_wire =
      M.add "signed" (Wire.Map (M.add "typ" (Wire.Data "root") signed))
        (M.add "foo" (Wire.Identifier "bar") M.empty)
    in
    Alcotest.check (result roo str_err) "bad map (no signatures) in wire"
      (Error "") (Root.of_wire bad_wire) ;
    let bad_wire =
      M.add "signatures" (Wire.List [])
        (M.add "foo" (Wire.Identifier "bar") M.empty)
    in
    Alcotest.check (result roo str_err) "bad map (no signed) in wire"
      (Error "") (Root.of_wire bad_wire) ;
    let e =
      let kref = Expression.Remote ( "foo", (`SHA256, "hash"), Uint.zero ) in
      Expression.Quorum (1, Expression.KS.singleton kref)
    in
    let root = { root with Root.valid = e } in
    let signed =
      M.add "valid" (Expression.to_wire e) signed
    in
    Alcotest.check (result roo str_err) "good wire with valid"
      (Ok (root, [])) (Root.of_wire (root_wire signed)) ;
    let key = "foobar", "now", `RSA, "rsakey" in
    let root = { root with Root.keys = M.add "foobar" key M.empty } in
    let signed =
      M.add "keys"
        (Wire.List [ Key.wire_raw key ]) signed
    in
    Alcotest.check (result roo str_err) "good wire with one key"
      (Ok (root, [])) (Root.of_wire (root_wire signed)) ;
    let key2 = Wire.List [ Wire.Identifier "foobar2" ; Wire.Data "now" ; Wire.Data "dsa=otherkey" ] in
    let signed =
      M.add "keys"
        (Wire.List [ Key.wire_raw key ; key2 ]) signed
    in
    Alcotest.check (result roo str_err) "good wire with one good key"
      (Ok (root, [])) (Root.of_wire (root_wire signed)) ;
    let badkey = Wire.List [ Wire.Identifier "foobar2" ; Wire.Data "now" ; Wire.Data "dsaotherkey" ] in
    let signed' =
      M.add "keys"
        (Wire.List [ Key.wire_raw key ; badkey ]) signed
    in
    Alcotest.check (result roo str_err) "bad wire with one good and one bad key"
      (Error "") (Root.of_wire (root_wire signed')) ;
    let wire =
      M.add "signatures" (Wire.List [ Wire.Data "wrong" ]) (root_wire signed)
    in
    Alcotest.check (result roo str_err) "bad wire with bad signature"
      (Error "") (Root.of_wire wire) ;
    let signature = "foobar", "now", `RSA_PSS_SHA256, "foobarsignature" in
    let wire =
      M.add "signatures" (Wire.List [ Signature.wire_raw signature ])
        (root_wire signed)
    in
    let root = { root with Root.signatures = M.add "foobar" signature M.empty } in
    Alcotest.check (result roo str_err) "good wire with good signature"
      (Ok (root, [])) (Root.of_wire wire)

  let tests = [
    "bad of_wire", `Quick, basic_bad_of_wire ;
    "good of_wire", `Quick, basic_good_of_wire ;
  ]
end

(* we accept everything *)
module VF = Conex_verify.Make(
  struct
    let verify_rsa_pss ~key:_ ~data:_ ~signature:_ _id = Ok ()
    let verify_ed25519 ~key:_ ~data:_ ~signature:_ _id = Ok ()
    let sha256 = Conex_mirage_crypto.V.sha256
  end)

module RepoTests = struct
  let target_t =
    Alcotest.testable Target.pp Target.equal

  let ctree =
    let module M = struct
      type t = (Digest.t * Uint.t * S.t) Tree.t
      let pp =
        let pp_triple ppf (digest, len, ids) =
          Fmt.pf ppf "%a len %s ids %a" Digest.pp digest (Uint.decimal len) S.pp ids
        in
        Tree.pp pp_triple
      let equal =
        let eq_triple (d, l, i) (d', l', i') =
          Digest.equal d d' && Uint.compare l l' = 0 &&
          S.equal i i'
        in
        Tree.equal eq_triple
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let target_dec () =
    let data = {|expr: [
        [size 0x1FF]
        [filename "foo/foo.1.0.0/opam"]
        [
          digest
          [
            "sha256=ccea69740e61ce074ed53019ac0dcde3c9602b00bdf21b12c0e53be2328f9b52"
          ]
        ]
      ]|}
    in
    let target = Target.{
        filename = [ "foo" ; "foo.1.0.0" ; "opam" ];
        digest = [ `SHA256, "ccea69740e61ce074ed53019ac0dcde3c9602b00bdf21b12c0e53be2328f9b52" ];
        size = Option.get (Uint.of_int 511)
      }
    in
    Alcotest.check (result target_t Alcotest.string) "basic target decoding"
      (Ok target) (Target.of_wire (wire_s data))

  let basic_good_target () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let target1 = {
      Target.filename = [ "foo.txt" ] ;
      digest = [ (`SHA256, "111111") ] ;
      size = Uint.of_int_exn 10
    }
    in
    let targets = [ target1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let expected =
      Tree.insert [ "foo.txt" ] ((`SHA256, "111111"), Uint.of_int_exn 10, S.of_list [id1 ; id2])
        Tree.empty
    in
    Alcotest.check ctree "basic target validation"
      expected
      (Conex_repository.collect_and_validate_targets
         keys root expr [ targets1 ; targets2 ])

  let partial_good_targets () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let target1 = {
      Target.filename = [ "foo.txt" ] ;
      digest = [ (`SHA256, "111111") ; (`SHA256, "222222") ] ;
      size = Uint.of_int_exn 10
    }
    in
    let target2 = { target1 with Target.filename = [ "bar.txt" ] } in
    let targets = [ target1 ; target2 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let targets = [
      target1 ;
      { target2 with Target.digest = [ (`SHA256, "111111") ] } ;
      { target2 with Target.size = Uint.of_int_exn 12 } ;
      { target1 with Target.filename = [ "frab.txt" ] }
    ] in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let expected =
      Tree.insert [ "bar.txt" ] ((`SHA256, "111111"), Uint.of_int_exn 10, S.of_list [ id1 ; id2 ])
        (Tree.insert [ "foo.txt" ] ((`SHA256, "222222"), Uint.of_int_exn 10, S.of_list [id1 ; id2])
           (Tree.insert [ "foo.txt" ] ((`SHA256, "111111"), Uint.of_int_exn 10, S.of_list [id1 ; id2])
              Tree.empty))
    in
    Alcotest.check ctree "basic target validation"
      expected
      (Conex_repository.collect_and_validate_targets
         keys root expr [ targets1 ; targets2 ])

  let wrong_epoch_target () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    and epoch' = Uint.of_int_exn 3
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch')
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let target1 = {
      Target.filename = [ "foo.txt" ] ;
      digest = [ (`SHA256, "111111") ] ;
      size = Uint.of_int_exn 10
    }
    in
    let targets = [ target1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let expected = Tree.empty in
    Alcotest.check ctree "target wrong epoch"
      expected
      (Conex_repository.collect_and_validate_targets
         keys root expr [ targets1 ; targets2 ])

  let wrong_len_target () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let target1 = {
      Target.filename = [ "foo.txt" ] ;
      digest = [ (`SHA256, "111111") ] ;
      size = Uint.of_int_exn 10
    }
    in
    let targets = [ target1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let targets = [
      { target1 with Target.size = Uint.of_int_exn 12 } ;
    ] in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let expected = Tree.empty in
    Alcotest.check ctree "target wrong len"
      expected
      (Conex_repository.collect_and_validate_targets
         keys root expr [ targets1 ; targets2 ])

  let wrong_hash_target () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let target1 = {
      Target.filename = [ "foo.txt" ] ;
      digest = [ (`SHA256, "111111") ] ;
      size = Uint.of_int_exn 10
    }
    in
    let targets = [ target1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let targets = [
      { target1 with Target.digest = [ (`SHA256, "123456") ] } ;
    ] in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let expected = Tree.empty in
    Alcotest.check ctree "target wrong hash"
      expected
      (Conex_repository.collect_and_validate_targets
         keys root expr [ targets1 ; targets2 ])

  let wrong_id_target () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let target1 = {
      Target.filename = [ "foo.txt" ] ;
      digest = [ (`SHA256, "111111") ] ;
      size = Uint.of_int_exn 10
    }
    in
    let targets = [ target1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1  ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let expected =
      Tree.insert [ "foo.txt" ] ((`SHA256, "111111"), Uint.of_int_exn 10, S.of_list [id1 ; id2])
        Tree.empty
    in
    Alcotest.check ctree "target wrong id (this succeeds)"
      expected
      (Conex_repository.collect_and_validate_targets
         keys root expr [ targets1 ; targets2 ]) ;
    let expected = Tree.empty in
    Alcotest.check ctree "keys is empty"
      expected
      (Conex_repository.collect_and_validate_targets
         M.empty root expr [ targets1 ; targets2 ]) ;
    Alcotest.check ctree "keys is insufficient"
      expected
      (Conex_repository.collect_and_validate_targets
         (M.remove id1 keys) root expr [ targets1 ; targets2 ]) ;
    Alcotest.check ctree "keys has wrong epoch"
      expected
      (Conex_repository.collect_and_validate_targets
         (M.add id1 (dgst1, Uint.of_int_exn 10) keys)
         root expr [ targets1 ; targets2 ]) ;
    Alcotest.check ctree "keys has wrong digest"
      expected
      (Conex_repository.collect_and_validate_targets
         (M.add id1 (dgst2, Uint.zero) keys)
         root expr [ targets1 ; targets2 ]) ;
    let targets2 = { targets2 with Targets.name = id1 } in
    Alcotest.check ctree "target wrong id (wrong id)"
      expected
      (Conex_repository.collect_and_validate_targets
         keys root expr [ targets1 ; targets2 ])

  let partial_good_targets_3 () =
    let id1 = "foo"
    and id2 = "bar"
    and id3 = "frab"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and dgst3 = (`SHA256, "098765")
    and epoch = Uint.zero
    and epoch' = Uint.of_int_exn 3
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch) ;
        Expression.Remote (id3, dgst3, epoch')
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) (M.add id3 (dgst3, epoch') M.empty)) in
    let target1 = {
      Target.filename = [ "foo.txt" ] ;
      digest = [ (`SHA256, "111111") ; (`SHA256, "222222") ] ;
      size = Uint.of_int_exn 10
    }
    in
    let target2 = { target1 with Target.filename = [ "bar.txt" ] } in
    let targets = [ target1 ; target2 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let targets = [
      { target1 with Target.digest = [ (`SHA256, "222211") ] } ;
      { target2 with Target.digest = [ (`SHA256, "111111") ] } ;
      { target1 with Target.filename = [ "frab.txt" ] }
    ] in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let targets = [
      { target1 with Target.digest = [ (`SHA256, "222222") ] };
      { target1 with Target.filename = [ "frab.txt" ] ; digest = [ (`SHA256, "2222221") ] }
    ] in
    let targets3 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = epoch' ;
        name = id3 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let expected =
      Tree.insert [ "bar.txt" ] ((`SHA256, "111111"), Uint.of_int_exn 10, S.of_list [ id1 ; id2 ])
        (Tree.insert [ "foo.txt" ] ((`SHA256, "222222"), Uint.of_int_exn 10, S.of_list [ id1 ; id3 ])
           Tree.empty)
    in
    Alcotest.check ctree "target partial good"
      expected
      (Conex_repository.collect_and_validate_targets
         keys root expr [ targets1 ; targets2 ; targets3 ])

  let wrong_path_target () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let target1 = {
      Target.filename = [ "foo.txt" ] ;
      digest = [ (`SHA256, "111111") ] ;
      size = Uint.of_int_exn 10
    }
    in
    let targets = [ target1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let expected = Tree.empty in
    Alcotest.check ctree "target wrong path"
      expected
      (Conex_repository.collect_and_validate_targets
         keys [ "foo" ] expr [ targets1 ; targets2 ])

  let part_wrong_path_target () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let target1 = {
      Target.filename = [ "foo" ; "foo.txt" ] ;
      digest = [ (`SHA256, "111111") ] ;
      size = Uint.of_int_exn 10
    }
    in
    let target2 = { target1 with Target.filename = [ "bar" ; "bar.txt" ] } in
    let targets = [ target1 ; target2 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let expected =
      Tree.insert [ "foo" ; "foo.txt" ] ((`SHA256, "111111"), Uint.of_int_exn 10, S.of_list [ id1 ; id2 ])
        Tree.empty
    in
    Alcotest.check ctree "target partially wrong path"
      expected
      (Conex_repository.collect_and_validate_targets
         keys [ "foo" ] expr [ targets1 ; targets2 ])

  let wrong_path_target2 () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let target1 = {
      Target.filename = [ "foo" ] ;
      digest = [ (`SHA256, "111111") ] ;
      size = Uint.of_int_exn 10
    }
    in
    let targets = [ target1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations = [] ;
        targets ; signatures = M.empty }
    in
    let expected = Tree.empty in
    Alcotest.check ctree "target wrong path"
      expected
      (Conex_repository.collect_and_validate_targets
         keys [ "foo" ] expr [ targets1 ; targets2 ])

  let dellist =
    let module M = struct
      type t = (path * Expression.t * bool * S.t) list
      let pp =
        let pp_e ppf (p, expr, t, ids) =
          Fmt.pf ppf "path %a expr %a terminating %b ids %a"
            pp_path p Expression.pp expr t S.pp ids
        in
        pp_list pp_e
      let equal a b =
        let eq_e (p, e, t, i) (p', e', t', i') =
          path_equal p p' && Expression.equal e e' && t = t' && S.equal i i'
        in
        List.length a = List.length b && List.for_all2 eq_e a b
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let basic_good_delegation () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let delegation1 = {
      Delegation.paths = [ [ "foo" ] ] ;
      valid = expr ;
      terminating = false ;
    }
    in
    let delegations = [ delegation1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let expected = [ ([ "foo" ], expr, false, S.of_list [id1 ; id2]) ] in
    Alcotest.check dellist "basic target validation"
      expected
      (Conex_repository.collect_and_validate_delegations
         keys root expr [ targets1 ; targets2 ])

  let basic_bad_expr_delegation () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let delegation1 = {
      Delegation.paths = [ [ "foo" ] ] ;
      valid = expr ;
      terminating = false ;
    }
    in
    let delegations = [ delegation1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let expr' = Expression.Quorum (1, Expression.KS.singleton (Expression.Remote (id2, dgst2, epoch))) in
    let delegations = [ { delegation1 with Delegation.valid = expr' } ] in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let expected = [] in
    Alcotest.check dellist "basic bad expr validation"
      expected
      (Conex_repository.collect_and_validate_delegations
         keys root expr [ targets1 ; targets2 ])

  let basic_bad_paths_delegation () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let delegation1 = {
      Delegation.paths = [ [ "foo" ] ] ;
      valid = expr ;
      terminating = false ;
    }
    in
    let delegations = [ delegation1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let delegations = [ { delegation1 with Delegation.paths = [ [ "bar" ] ] } ] in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let expected = [] in
    Alcotest.check dellist "basic bad paths validation"
      expected
      (Conex_repository.collect_and_validate_delegations
         keys root expr [ targets1 ; targets2 ])

  let basic_bad_terminating_delegation () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let delegation1 = {
      Delegation.paths = [ [ "foo" ] ] ;
      valid = expr ;
      terminating = false ;
    }
    in
    let delegations = [ delegation1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let delegations = [ { delegation1 with Delegation.terminating = true } ] in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let expected = [] in
    Alcotest.check dellist "basic bad terminating validation"
      expected
      (Conex_repository.collect_and_validate_delegations
         keys root expr [ targets1 ; targets2 ])

  let basic_bad_quorum_delegation () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let delegation1 = {
      Delegation.paths = [ [ "foo" ] ] ;
      valid = expr ;
      terminating = false ;
    }
    in
    let delegations = [ delegation1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let delegations = [ ] in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let expected = [] in
    Alcotest.check dellist "basic bad quorum validation"
      expected
      (Conex_repository.collect_and_validate_delegations
         keys root expr [ targets1 ; targets2 ])

  let multiple_good_delegations () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let delegation1 = {
      Delegation.paths = [ [ "foo" ] ; [ "bar" ] ] ;
      valid = expr ;
      terminating = false ;
    }
    in
    let delegations = [ delegation1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let delegations = [ { delegation1 with Delegation.paths = [ [ "bar" ] ; [ "baz" ] ; [ "foo" ] ] } ] in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let expected = [
      ([ "foo" ], expr, false, S.of_list [id1 ; id2]) ;
      ([ "bar" ], expr, false, S.of_list [id1 ; id2])
    ] in
    Alcotest.check dellist "multiple good delegations"
      expected
      (Conex_repository.collect_and_validate_delegations
         keys root expr [ targets1 ; targets2 ])

  let multiple_good_delegations_different_expr () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let expr2 = Expression.Quorum (1, Expression.KS.singleton (Expression.Remote (id2, dgst2, epoch))) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let delegation1 = {
      Delegation.paths = [ [ "foo" ] ; [ "bar" ] ] ;
      valid = expr ;
      terminating = false ;
    }
    in
    let delegation2 = {
      Delegation.paths = [ [ "baz" ] ; [ "foobar" ] ] ;
      valid = expr2 ;
      terminating = true
    }
    in
    let delegations = [ delegation1 ; delegation2 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let delegations = [
      { delegation1 with Delegation.paths = [ [ "bar" ] ; [ "baz" ] ] } ;
      { delegation2 with Delegation.paths = [ [ "foobar" ] ; [ "foo" ] ] }
    ]
    in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let expected = [
      ([ "foobar" ], expr2, true, S.of_list [id1 ; id2]) ;
      ([ "bar" ], expr, false, S.of_list [id1 ; id2])
    ] in
    Alcotest.check dellist "multiple good delegations"
      expected
      (Conex_repository.collect_and_validate_delegations
         keys root expr [ targets1 ; targets2 ])

  let basic_bad_path_delegation () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let delegation1 = {
      Delegation.paths = [ [ "foo" ] ] ;
      valid = expr ;
      terminating = false ;
    }
    in
    let delegations = [ delegation1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let expected = [] in
    Alcotest.check dellist "basic bad path validation"
      expected
      (Conex_repository.collect_and_validate_delegations
         keys [ "bar" ] expr [ targets1 ; targets2 ])

  let partial_bad_path_delegation () =
    let id1 = "foo"
    and id2 = "bar"
    and dgst1 = (`SHA256, "abcdef")
    and dgst2 = (`SHA256, "123456")
    and epoch = Uint.zero
    in
    let expr = Expression.Quorum (2, Expression.KS.of_list [
        Expression.Remote (id1, dgst1, epoch) ;
        Expression.Remote (id2, dgst2, epoch)
      ]) in
    let keys = M.add id1 (dgst1, epoch) (M.add id2 (dgst2, epoch) M.empty) in
    let delegation1 = {
      Delegation.paths = [ [ "foo" ] ; [ "bar" ] ; [ "bar" ; "foobar" ] ] ;
      valid = expr ;
      terminating = false ;
    }
    in
    let delegations = [ delegation1 ] in
    let targets1 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id1 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let targets2 =
      { Targets.created = "now" ; counter = Uint.zero ; epoch = Uint.zero ;
        name = id2 ; keys = M.empty ; valid = expr ; delegations ;
        targets = [] ; signatures = M.empty }
    in
    let expected = [ ([ "bar" ; "foobar" ], expr, false, S.of_list [id1 ; id2]) ] in
    Alcotest.check dellist "basic bad path validation"
      expected
      (Conex_repository.collect_and_validate_delegations
         keys [ "bar" ] expr [ targets1 ; targets2 ])

  let tests = [
    "decoding a target", `Quick, target_dec ;
    "basic good target", `Quick, basic_good_target ;
    "partial good targets", `Quick, partial_good_targets ;
    "wrong epoch target", `Quick, wrong_epoch_target ;
    "wrong length target", `Quick, wrong_len_target ;
    "wrong hash target", `Quick, wrong_hash_target ;
    "wrong id target", `Quick, wrong_id_target ;
    "partial good targets 3", `Quick, partial_good_targets_3 ;
    "wrong path target", `Quick, wrong_path_target ;
    "partially wrong target path", `Quick, part_wrong_path_target ;
    "wrong path target", `Quick, wrong_path_target2 ;
    "basic good delegation", `Quick, basic_good_delegation ;
    "basic bad expr delegation", `Quick, basic_bad_expr_delegation ;
    "basic bad paths delegation", `Quick, basic_bad_paths_delegation ;
    "basic bad terminating delegation", `Quick, basic_bad_terminating_delegation ;
    "basic bad quorum delegation", `Quick, basic_bad_quorum_delegation ;
    "multiple good delegations", `Quick, multiple_good_delegations ;
    "multiple good delegations different expressions", `Quick, multiple_good_delegations_different_expr ;
    "basic bad path delegations", `Quick, basic_bad_path_delegation ;
    "basic partial path delegations", `Quick, partial_bad_path_delegation ;
  ]
end


module BasicTests (V : Conex_verify.S) (R : Conex_verify.S_BACK) = struct
  let verr =
    let module M = struct
      type t = Conex_verify.error
      let pp = Conex_verify.pp_error
      let equal a b = match a, b with
        | `InvalidBase64Encoding id, `InvalidBase64Encoding id' -> id_equal id id'
        | `InvalidSignature id, `InvalidSignature id' -> id_equal id id'
        | `InvalidPublicKey id, `InvalidPublicKey id' -> id_equal id id'
        (* for OpenSSL *)
        | `InvalidBase64Encoding _, `InvalidSignature _ -> true
        | `InvalidBase64Encoding _, `InvalidPublicKey _ -> true
        | _ -> false
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let raw_sign p d = match Conex_mirage_crypto.C.sign p d with
    | Ok s -> s
    | Error e -> Alcotest.fail e

  let raw_sig_good data () =
    let pid = "foobar" in
    let pub, p = gen_pub () in
    let pu = match pub with (_, _, `RSA, k) -> k | (_, _, `Ed25519, _) -> Alcotest.fail "should be RSA" in
    let d = Wire.to_string (to_be_signed data "timestamp" pid `RSA_PSS_SHA256) in
    let signature = raw_sign (Obj.magic p) d in
    Alcotest.check (result Alcotest.unit verr)
      "signature is good" (Ok ())
      (R.verify_rsa_pss pid ~key:pu ~data:d ~signature)

  let raw_sig_bad ~openssl data () =
    let pid = "foobar" in
    let pub, p = gen_pub () in
    let pu = match pub with (_, _, `RSA, k) -> k | (_, _, `Ed25519, _) -> Alcotest.fail "should be RSA" in
    let d = Wire.to_string (to_be_signed data "timestamp" pid `RSA_PSS_SHA256) in
    let signature = raw_sign (Obj.magic p) d in
    let badd = d ^ "=" in
    Alcotest.check (result Alcotest.unit verr)
      "signature is bad (bad data)" (Error (`InvalidSignature pid))
      (R.verify_rsa_pss pid ~key:pu ~data:badd ~signature) ;
    let badsig = "foo" ^ signature in
    Alcotest.check (result Alcotest.unit verr)
      "signature is bad (invalid base64)" (Error (`InvalidBase64Encoding pid))
      (R.verify_rsa_pss pid ~key:pu ~data:d ~signature:badsig) ;
    let badsig =
      if openssl then
        signature ^ "=fdd"
      else
        (* the following is fine with OpenSSL :/ *)
        signature ^ "="
    in
    Alcotest.check (result Alcotest.unit verr)
      "signature is bad (invalid base64) take 2" (Error (`InvalidBase64Encoding pid))
      (R.verify_rsa_pss pid ~key:pu ~data:d ~signature:badsig) ;
    let badkey = pu ^ "=" in
    Alcotest.check (result Alcotest.unit verr)
      "signature is bad (invalid key)"
      (Error (if openssl then `InvalidSignature pid else `InvalidPublicKey pid))
      (R.verify_rsa_pss pid ~key:badkey ~data:d ~signature)

  let raw_sigs ~openssl =
    let tests = [
      M.empty ;
      M.add "foo" (Wire.Data "foobar") M.empty ;
      M.add "foo" (Wire.Identifier "foobar") M.empty ;
      M.add "foo" (Wire.Bigint Uint.zero) M.empty ;
      M.add "barf" (Wire.Smallint 42) (M.add "foo" (Wire.Bigint Uint.zero) M.empty) ;
    ] in
    fst (
      List.fold_left (fun (acc, i) data ->
          acc @ [
            ("sign and verify is good " ^ string_of_int i, `Quick, raw_sig_good data) ;
            ("sign and verify is bad " ^ string_of_int i, `Quick, raw_sig_bad ~openssl data)
          ], succ i) ([], 0) tests)

  let ver =
    let module M = struct
      type t = identifier Digest_map.t * Conex_verify.error list
      let pp ppf (ids, errs) =
        Format.fprintf ppf "s: %a@.errs: %a"
          (Digest_map.pp pp_id) ids
          (pp_list Conex_verify.pp_error) errs
      let equal (ids, err) (ids', err') =
        let e_eq a b = match a, b with
          | `UnknownKey id, `UnknownKey id' -> id_equal id id'
          | `InvalidBase64Encoding id, `InvalidBase64Encoding id' -> id_equal id id'
          | `InvalidSignature id, `InvalidSignature id' -> id_equal id id'
          | `InvalidPublicKey id, `InvalidPublicKey id' -> id_equal id id'
          | _ -> false
        in
        List.length err = List.length err' &&
        List.for_all2 e_eq err err' &&
        Digest_map.equal id_equal ids ids'
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

  let sign_verify_root () =
    let pub, p = gen_pub () in
    let id = "foobar" in
    let dgst = Key.keyid V.raw_digest pub in
    let expr = Expression.Quorum (1, Expression.KS.singleton (Expression.Local id)) in
    let keys = M.add id pub M.empty in
    let root = {
      Root.created = "yesterday" ;
      counter = Uint.zero ;
      epoch = Uint.zero ;
      name = "root" ;
      datadir = [ "somewhere" ] ;
      keydir = [ "elsewhere" ] ;
      keys = keys ;
      valid = expr ;
      roles = Root.RM.empty ;
      signatures = M.empty
    } in
    match PRIV.sign (Root.wire_raw root) "now!" id (Obj.magic p) with
    | Error e -> Alcotest.fail e
    | Ok signature ->
      let raw_root = Root.wire_raw root in
      Alcotest.check ver "verify root works"
        (Digest_map.add dgst id Digest_map.empty, [])
        (V.verify raw_root keys (M.add id signature M.empty)) ;
      Alcotest.check ver "verify root fails"
        (Digest_map.empty, [])
        (V.verify M.empty keys M.empty) ;
      Alcotest.check ver "verify root fails!"
        (Digest_map.empty, [ `InvalidSignature id ])
        (V.verify M.empty keys (M.add id signature M.empty)) ;
      let wrong_keys = M.add "bar" pub M.empty in
      Alcotest.check ver "verify root fails (wrong key)!"
        (Digest_map.empty, [ `UnknownKey id ])
        (V.verify M.empty wrong_keys (M.add id signature M.empty))

(*    <add signature>
    <to_wire>
    <of_wire>
    <verify>
      <maybe play a bit with modifyin root and attempt to verify> *)

  let sign_tests ~openssl = raw_sigs ~openssl @ [
      "sign and verify root", `Quick, sign_verify_root ;
    ]
  let tests ~openssl prefix =
    [ (prefix ^ "Signature", sign_tests ~openssl) ]
end

module MC = BasicTests (Conex_mirage_crypto.NC_V) (Conex_mirage_crypto.V)
module OC = BasicTests (Conex_openssl.O_V) (Conex_openssl.V)

let tests = ("Expressions", ExprTests.tests) ::
            ("Keys", KeyTests.tests) ::
            ("Signatures", SigTests.tests) ::
            ("Digests", DigestTests.tests) ::
            ("Roots", RootTests.tests) ::
            ("Repos", RepoTests.tests) ::
            MC.tests ~openssl:false "Mirage_crypto"
