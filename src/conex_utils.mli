
(** String, unsigned integers, logging, collections, and more *)

(** {1 Sets, Maps, List utils} *)

(** [S] is a string set. *)
module S : sig
  (** {1 String sets} *)
  include Set.S with type elt = string

  (** [of_list xs] transforms the string list [xs] to a set. *)
  val of_list : string list -> t

  (** [pp fmt t] pretty prints [t]. *)
  val pp : Format.formatter -> t -> unit
end

(** [M] is a [Map] which keys are strings. *)
module M : sig

  (** {1 String maps} *)
  include Map.S with type key = string

  (** [pp pp_e fmt t] pretty prints [t] using [pp_e] for printing the values. *)
  val pp : (Format.formatter -> 'a -> unit) -> Format.formatter -> 'a t -> unit
end

(** [filter_map f xs] is [xs'], a list which contains all elements where [f]
    resulted in [Some _]. *)
val filter_map : f:('a -> 'b option) -> 'a list -> 'b list

(** {1 Format} *)

(** ['a fmt] is the signature for pretty printers. *)
type 'a fmt = Format.formatter -> 'a -> unit

(** [pp_list pp] is a pretty printer for a list (surrounded by square brackets,
    elements are separated by semicolon).  The [pp] is be a pretty printer for
    list elements. *)
val pp_list : 'a fmt -> 'a list fmt

(** [str_pp pp a] results in a string applying the pretty-printer to the value. *)
val str_pp : 'a fmt -> 'a -> string

(** {1 Result combinators} *)

(** [guard pred err] is either [Ok ()] (if [pred] holds), [Error err] otherwise. *)
val guard : bool -> 'a -> (unit, 'a) result

(** [foldM f a xs] applies [f] to each element of [xs], returns either [Ok] and
    the produced value, or [Error]. *)
val foldM : ('a -> 'b -> ('a, 'c) result) -> 'a -> 'b list -> ('a, 'c) result

(** [iterM f xs] applies [f] to each element of [xs], returns either [Ok] and
    the produced value, or [Error]. *)
val iterM : ('a -> (unit, 'b) result) -> 'a list -> (unit, 'b) result

(** [foldS f a s] applies [f] to each element of the set [s], returns either
    [Ok] and the produced value, or [Error]. *)
val foldS : ('a -> string -> ('a, 'c) result) -> 'a -> S.t -> ('a, 'c) result

(** [err_to_str pp res] is either [Ok a] or [Error str] where [str] was produced
    by {!str_pp}. *)
val err_to_str : 'b fmt -> ('a, 'b) result -> ('a, string) result


(** {1 String} *)

(** Some [String] utilities implemented here to avoid external
    dependencies.  This is a subset of
    {{:http://erratique.ch/software/astring}Astring}. *)
module String : sig

  (** Our string type is an OCaml [string] *)
  type t = string

  (** [cuts sep str] separates [str] into multiple substrings, stripping out the
      separating character [sep].  [String.concat "/" (String.cuts '/' xs)] is
      the identity. *)
  val cuts : char -> t -> t list

  (** [cut sep str] cuts the string [str] at the first occurence of [sep] into
      its left and right parts.  If [sep] is not found, [None] is returned.
      If [Some (a, b)] is returned, [a ^ sep ^ b] is equal to [str]. *)
  val cut : char -> t -> (t * t) option

  (** [is_prefix ~prefix str] is [true] if [str] begins with [prefix], [false]
      otherwise. *)
  val is_prefix : prefix:t -> t -> bool

  (** [slice ~start ~stop str] slices [str] into a smaller piece, starting at
      offset [start] (default 0), ending at [stop] (default [String.length]). *)
  val slice : ?start:int -> ?stop:int -> t -> t

  (** [to_lower str] converts all printable ASCII characters to lowercase. *)
  val to_lower : t -> t

  (** [is_ascii ~p str] is [true] if all characters in [str] are ASCII
      characters: 0-9, a-z, A-Z OR satisfy [p].  Otherwise [false]. *)
  val is_ascii : ?p:(char -> bool) -> t -> bool

  (** [trim str] removes leading and trailing whitespaces of [str]. *)
  val trim : t -> t

  (** [get str offset] retrieves the character at [offset] in [str]. *)
  val get : t -> int -> char

  (** [concat sep xs] concatenates all [xs], using [sep] as separator. *)
  val concat : t -> t list -> t

  (** [compare a b] compares [a] with [b] using [String.compare]. *)
  val compare : t -> t -> int

  (** [length str] is the byte length of [str]. *)
  val length : t -> int

  (** [compare_insensitive a b] first converts [a] and [b] to lowercase strings,
      then uses [compare]. *)
  val compare_insensitive : t -> t -> int

  (** [equal a b] is [String.equal a b]. *)
  val equal : t -> t -> bool
end

(** {1 Unsigned integers} *)

(** 64 bit unsigned integer with explicit overflow behaviour (see
    {!Uint.succ}). *)
module Uint : sig

  (** A 64 bit unsigned integer (using a [int64]). *)
  type t

  (** [zero] is the smallest member. *)
  val zero : t

  (** [compare a b] is [res]: 0 if [a = b], -1 if [a < b], 1 if [a > b] *)
  val compare : t -> t -> int

  (** [succ t] is [carry, next]: if [carry] is true, an overflow happened.
      [next] is always the next integer in the [Z/2^64-1Z] group. *)
  val succ : t -> bool * t

  (** [to_string t] is [t] converted to a string in hexadecimal ([0x%LX]).  *)
  val to_string : t -> string

  (** [pp] is a pretty printer *)
  val pp : t fmt

  (** [decimal t] is [t] converted to a string in decimal ([%Lu]).  *)
  val decimal : t -> string

  (** [of_string s] attempts to parse the string [s] as hexadecimal encoded
      number using [Int64.of_string s]. *)
  val of_string : string -> t option

  (** [of_float f] is [Int64.of_float f] if [f >= 0.0]. *)
  val of_float : float -> t option

  (** [of_int i] is [Int64.of_int i] if [i >= 0]. *)
  val of_int : int -> t option

  (** [of_int_exn i] is [Int64.of_int i] if [i >= 0].
      @raise [Invalid_argument] on failure. *)
  val of_int_exn : int -> t
end

(** [Uint_map] is a [Map] which keys are Uint.t. *)
module Uint_map : sig

  (** {1 String maps} *)
  include Map.S with type key = Uint.t
end

(** {1 Logging} *)

(** [LOGS] is a subset of the {{:http://erratique.ch/software/logs}Logs}
    library, providing four log streams. *)
module type LOGS = sig

  (** Tag, as in logs *)
  module Tag : sig type set end

  (** msgf *)
  type ('a, 'b) msgf =
    (?header:string -> ?tags:Tag.set ->
     ('a, Format.formatter, unit, 'b) format4 -> 'a) -> 'b
  type 'a log = ('a, unit) msgf -> unit

  type src

  (** [warn_count ()] is the number of warning messages. *)
  val warn_count : unit -> int

  (** [debug k] logs [k], a to the debug stream *)
  val debug : ?src:src -> 'a log

  (** [info k] logs [k], a to the information stream *)
  val info : ?src:src -> 'a log

  (** [warn k] logs [k], a to the warning stream *)
  val warn : ?src:src -> 'a log
end

(** {1 File system types} *)

(** The sum type of possible file types we expect *)
type file_type = File | Directory

(** A [path] is a list of strings *)
type path = string list

(** [root] is the root path. *)
val root : path

(** [path_to_string path] is {{!Conex_utils.String.concat}String.concat} ["/"
    path].
    @raise [Invalid_argument] if [path] includes either "." or "..". *)
val path_to_string : path -> string

(** [string_to_path str] is {{!Conex_utils.String.cuts}String.cuts} ["/"
    str] and ensuring no empty segments, ".", or ".." be present. If [str]
    contains a leading "/", it is discarded. *)
val string_to_path : string -> (path, string) result

(** [string_to_path_exb str] is {{!Conex_utils.String.cuts}String.cuts} ["/"
    str] and ensuring no empty segments, ".", or ".." be present. If [str]
    contains a leading "/", it is discarded.
    @raise [Invalid_argument] if [path] is invalid. *)
val string_to_path_exn : string -> path

(** [path_equal p p'] is [true] if [p] and [p'] are equal. *)
val path_equal : path -> path -> bool

(** [subpath ~parent p] is [true] if [p] starts with all segments of [parent]. *)
val subpath : parent:path -> path -> bool

(** [strip_prefix ~prefix p] strips the prefix from [p]
    (only if [subpath ~paren:prefix p] is true). Returns [None] otherwise. *)
val strip_prefix : prefix:path -> path -> path option

(** [pp_path] is a pretty printer for a path. *)
val pp_path : path fmt

(** An [item] is a type and its payload *)
type item = file_type * string

(** {1 Tree} *)

(** [Tree] is a simple tree datatype, edge is a [string], values are ['a lists]. *)
module Tree : sig

  (** The main tree type *)
  type 'a t

  (** [equal eq a b] compares [a] with [b], using [eq] to compare values. *)
  val equal : ('a -> 'a -> bool) -> 'a t -> 'a t -> bool

  (** [empty] is the only constructor of a tree. *)
  val empty : 'a t

  val is_empty : 'a t -> bool

  val sub : path -> 'a t -> 'a t

  (** [fold f acc t] folds [f] over [t], using the accumulator [acc]. *)
  val fold : (path -> 'a list -> 'b -> 'b) -> 'b -> 'a t -> 'b

  (** [pp pp_e ppf t] pretty prints the tree [t] using [pp_e] for printing values. *)
  val pp : (Format.formatter -> 'a -> unit) -> Format.formatter -> 'a t -> unit

  (** [lookup path t] returns either [Some values] or [None]. *)
  val lookup : path -> 'a t -> 'a list option

  (** [lookup_prefix path t] finds the closest non-empty ['a] on [path]. *)
  val lookup_prefix : path -> 'a t -> 'a list

  (** [insert path value t] inserts [value] into [t] at [path].  If the key is
      already in the tree, its value is prepended. *)
  val insert : path -> 'a -> 'a t -> 'a t
end

(** [timestamp_to_int64 timestamp] attempts to convert the provided RFC 3339
    timestamp to an int64 representing the seconds since Unix epoch
    (1970-01-01). When decoding leads to an error, or the timestamp is not in
    range (of the int64), an error message is returned. *)
val timestamp_to_int64 : string -> (int64, string) result
