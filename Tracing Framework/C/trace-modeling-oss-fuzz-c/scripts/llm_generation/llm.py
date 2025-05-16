import pandas as pd
import random
import os
import backoff
from openai import RateLimitError, Timeout, APIError
from openai import OpenAI
import json

def make_example(signature, harness):
    return """Problem:
```
{signature}
```

Solution:
```
{harness}
```
""".format(signature=signature, harness=harness)

PROMPT="""You are a security testing engineer who wants to write a C++ program to execute all lines in a given function by defining and initialising its parameters in a suitable way before fuzzing the function through `LLVMFuzzerTestOneInput`.

Carefully study the function signature and its parameters, then follow the example problems and solutions to answer the final problem. YOU MUST call the function to fuzz in the solution.

Try as many variations of these inputs as possible. Do not use a random number generator such as `rand()`.

All variables used MUST be declared and initialized. Carefully make sure that the variable and argument types in your code match and compiles successfully. Add type casts to make types match.

Do not create new variables with the same names as existing variables.
WRONG:
```
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  void* data = Foo();
}
```

EXTREMELY IMPORTANT: If you write code using `goto`, you MUST MUST also declare all variables BEFORE the `goto`. Never introduce new variables after the `goto`.
WRONG:
```
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int a = bar();
  if (!some_function()) goto EXIT;
  Foo b = target_function(data, size);
  int c = another_func();
EXIT:
  return 0;
}
```
CORRECT:
```
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int a = bar();
  Foo b;
  int c;

  if (!some_function()) goto EXIT;
  b = target_function(data, size);
  c = another_func()
EXIT:
  return 0;
}
```

If an example provided for the same library includes a unique header file, then it must be included in the solution as well."""

PROMPT_TEMPLATE = """{prompt}

Do not use FuzzedDataProvider. Just use the input data from the parameters.
Do not use C++ headers, only C.

{examples}


You MUST call `{signature}` in your solution!
Problem:
```
{signature}
```

Solution:
"""
# TODO: don't use FuzzedDataProvider!

def get_example_text():
    # Get in-context examples for project
    # examples = database[database["project"] == project]
    examples = [
        {
            "signature": "BGD_DECLARE(void) gdImageString (gdImagePtr im, gdFontPtr f, int x, int y, unsigned char *s, int color)",
            "harness": """#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "gd.h"
#include "gdfontg.h"
#include "gdfontl.h"
#include "gdfontmb.h"
#include "gdfonts.h"
#include "gdfontt.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider stream(data, size);
  const uint8_t slate_width = stream.ConsumeIntegral<uint8_t>();
  const uint8_t slate_height = stream.ConsumeIntegral<uint8_t>();
  gdImagePtr slate_image = gdImageCreateTrueColor(slate_width, slate_height);
  if (slate_image == nullptr) {
    return 0;
  }

  const int x_position = stream.ConsumeIntegral<int>();
  const int y_position = stream.ConsumeIntegral<int>();
  const int text_color = stream.ConsumeIntegral<int>();
  const gdFontPtr font_ptr = stream.PickValueInArray(
      {gdFontGetGiant(), gdFontGetLarge(), gdFontGetMediumBold(),
       gdFontGetSmall(), gdFontGetTiny()});
  const std::string text = stream.ConsumeRemainingBytesAsString();

  gdImageString(slate_image, font_ptr, x_position, y_position,
                reinterpret_cast<uint8_t*>(const_cast<char*>(text.c_str())),
                text_color);
  gdImageDestroy(slate_image);
  return 0;
}""",
        },
        {
            "signature": "MPG123_EXPORT int mpg123_decode(mpg123_handle *mh, const unsigned char *inmemory, size_t inmemsize, unsigned char *outmemory, size_t outmemsize, size_t *done )",
            "harness": """#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "mpg123.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool initialized = false;
  if (!initialized) {
    mpg123_init();
    initialized = true;
  }
  int ret;
  mpg123_handle* handle = mpg123_new(nullptr, &ret);
  if (handle == nullptr) {
    return 0;
  }

  ret = mpg123_param(handle, MPG123_ADD_FLAGS, MPG123_QUIET, 0.);
  if(ret == MPG123_OK)
    ret = mpg123_open_feed(handle);
  if (ret != MPG123_OK) {
    mpg123_delete(handle);
    return 0;
  }

  std::vector<uint8_t> output_buffer(mpg123_outblock(handle));

  size_t output_written = 0;
  // Initially, start by feeding the decoder more data.
  int decode_ret = MPG123_NEED_MORE;
  FuzzedDataProvider provider(data, size);
  while ((decode_ret != MPG123_ERR)) {
    if (decode_ret == MPG123_NEED_MORE) {
      if (provider.remaining_bytes() == 0
          || mpg123_tellframe(handle) > 10000
          || mpg123_tell_stream(handle) > 1<<20) {
        break;
      }
      const size_t next_size = provider.ConsumeIntegralInRange<size_t>(
          0,
          provider.remaining_bytes());
      auto next_input = provider.ConsumeBytes<unsigned char>(next_size);
      decode_ret = mpg123_decode(handle, next_input.data(), next_input.size(),
                                 output_buffer.data(), output_buffer.size(),
                                 &output_written);
    } else if (decode_ret != MPG123_ERR && decode_ret != MPG123_NEED_MORE) {
      decode_ret = mpg123_decode(handle, nullptr, 0, output_buffer.data(),
                                 output_buffer.size(), &output_written);
    } else {
      // Unhandled mpg123_decode return value.
      abort();
    }
  }

  mpg123_delete(handle);

  return 0;
}""",
        }
    ]
    # Exclude function
    # examples = [e for e in examples if function not in e["signature"]]
    # Keep only a few in-context examples
    # examples = random.sample(examples, 3)
    return "\n\n".join([make_example(e["signature"], e["harness"]) for e in examples])

def make_prompt(row):
    examples_text = get_example_text()
    # examples_text = get_example_text(row["project"], row["function"])
    return PROMPT_TEMPLATE.format(prompt=PROMPT, examples=examples_text, signature=" ".join(row["signature"].strip().split()))

def append_jsonl_row(data, fpath):
    with open(fpath, "a") as f:
        f.write(json.dumps(data) + "\n")



@backoff.on_exception(backoff.expo,
                      (RateLimitError,),
                      max_tries=10)
@backoff.on_exception(backoff.constant(5),
                      (Timeout, APIError),
                      max_tries=5)
def make_request(prompt):
    client = OpenAI(
        # This is the default and can be omitted
        api_key=os.environ.get("OPENAI_API_KEY"),
    )
    chat_completion = client.chat.completions.create(
        messages=[
            {
                "role": "user",
                "content": prompt,
            }
        ],
        model="gpt-3.5-turbo",
    )
    return chat_completion

def make_completion(data):
    try:
        prompt = make_prompt(data)
        with open(f'prompt_{data["function"]}.txt', "w") as f:
            print(prompt, file=f, end="")
        # return {"code": "success", "response": make_request(prompt)}
    except Exception:
        pass
        # TODO: return error response
        # return {"code": "error"}

def make_completions(df, fpath):
    # if os.path.exists(fpath):
    #     os.unlink(fpath)
    for i, row in df.iterrows():
        result = make_completion(row)
        # append_jsonl_row(result, fpath)

if __name__ == "__main__":
    random.seed(0)
    # df = pd.read_json("/home/XXX/Code/trace-modeling/oss-fuzz-c/code/libucl/functions.jsonl", lines=True)
    df = pd.read_json("/home/XXX/Code/trace-modeling/oss-fuzz-c/code/apache-httpd/functions.jsonl", lines=True)
    # df = df.head(5)
    df = df[df["signature"].isin([
        "int get_line(char *s, int n, apr_file_t *f)",
        "void add_password(const char *user, const char *realm, apr_file_t *f)",
        "void dumpConfig (rotate_config_t *config)",
        "void doRotate(rotate_config_t *config, rotate_status_t *status)",
        "int exists(char *fname, apr_pool_t *pool)",
    ])]
    df["prompt"] = df.apply(make_prompt, axis=1)
    # dst_fpath = "/home/XXX/Code/trace-modeling/oss-fuzz-c/code/libucl/prompt_responses.jsonl"
    make_completions(df, None)
