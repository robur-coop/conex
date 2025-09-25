(** IO operations

    Conex relies on providers to read data from and write data to.  Each access
    consists of a {!path} used as key.  Only basic file types are supported (no
    symbolic links).
*)

open Conex_utils
open Conex_resource

(** {1 IO provider} *)

(** A provider contains its base directory, a description, and read/write/exist
    functionality.  TODO: define this as a module type. *)
type t = {
  basedir : string ;
  description : string ;
  file_type : path -> (file_type, string) result ;
  read : path -> (string, string) result ;
  write : path -> string -> (unit, string) result ;
  read_dir : path -> (item list, string) result ;
  exists : path -> bool ;
}

(** [pp t] is a pretty printer for [t]. *)
val pp : t fmt

(** {1 Reading of resource files} *)

(** The variant of read and parse errors. *)
type r_err = [
  | `NotFound of typ * name
  | `ParseError of typ * name * string
  | `NameMismatch of typ * name * name
  | `InvalidPath of name * path
]

(** [pp_r_err] is a pretty printer for {!r_err}. *)
val pp_r_err : r_err fmt

module Make (L : LOGS) : sig
  val read_root : t -> name -> (Root.t * string list, [> r_err ]) result

  val write_root : t -> Root.t -> (unit, string) result

  val read_timestamp : t -> name -> (Timestamp.t * string list, [> r_err ]) result

  val write_timestamp : t -> Timestamp.t -> (unit, string) result

  val read_snapshot : t -> name -> (Snapshot.t * string list, [> r_err ]) result

  val write_snapshot : t -> Snapshot.t -> (unit, string) result

  val targets : t -> Root.t -> identifier list

  val read_targets : t -> Root.t -> bool -> identifier -> (Targets.t * string list, [> r_err ]) result

  val write_targets : t -> Root.t -> Targets.t -> (unit, string) result

  val compute_checksum_file : t -> (string -> Digest.t) -> path ->
    (Target.t, string) result

  val compute_checksum : prefix:path -> t -> bool -> (string -> Digest.t) -> path ->
    (Target.t list, string) result

  val compute_checksum_tree : ?prefix:path -> t -> (string -> Digest.t) ->
    ((Digest.t * Uint.t) Tree.t, string) result
end
