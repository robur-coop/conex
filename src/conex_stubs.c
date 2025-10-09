#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>


CAMLprim value
conex_compare_string(value val_buf1, value val_buf2, value val_len)
{
  int res = memcmp(String_val(val_buf1), String_val(val_buf2), Long_val(val_len));
  return Val_int(res);
}
