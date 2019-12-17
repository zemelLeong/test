import pandas as pd
import re
import os

pd.set_option('display.max_rows', 10)
pd.set_option('display.max_columns', 500)
pd.set_option('display.width', 1000)

pattern_intls = re.compile(r'intl.get\(.*\).d\([^)]*\)')
pattern_intl_code = re.compile(r'(?<=intl.get\().*?(?=\).d)')
pattern_intl_value = re.compile(r'(?<=\).d\().*?(?=\))')

pattern_code_prefix = re.compile(r'(?<=\${).*(?=}\.)')
pattern_var_value1 = r"(?<=const {0}).*(?=['`];)"
pattern_var_value2 = re.compile(r"(?<=[`']).*")

ignore_file_list = [
  r'.\routes\hitf\InterfaceLogs\index.js',
  r'.\routes\sodr\OrderRelease\Detail\AssociatedDoc.js',
  r'.\routes\sodr\OrderRelease\Detail\List.js',
  r'.\routes\ssrc\InquiryHall\Drawer.js',
  r'.\routes\ssrc\InquiryHall\TableList.js',
  r'.\routes\ssrc\InquiryHall\Update\index.js',
]
ignore_code_list = [
  '$entity.order.type.name'
]

file_list = []
for root, dirs, files in os.walk('.', topdown=True):
  for file in files:
    file_list.append(os.path.join(root, file))

result_df = pd.DataFrame()
for file in file_list:
  if file.endswith(".js"):
    if file in ignore_file_list:
      print("忽略文件：{0}".format(file))
      continue

    with open(file, "r", encoding="utf8") as f:
      print("开始解析文件: {0}".format(file))
      file_content = f.read()
      file_content_clear = file_content  # .replace("\n", " ")
      intls = pattern_intls.findall(file_content_clear)
      tmp_df = pd.DataFrame(data=intls, columns=['intl'])
      codes = [pattern_intl_code.search(x).group().replace("'", "").replace("`", "") for x in intls]
      values = [pattern_intl_value.search(x).group().replace("'", "").replace("`", "") for x in intls]

      prefix_set = set()
      for index, code in enumerate(codes):
        if "$" in code and code not in ignore_code_list:
          try:
            prefix_set.add(pattern_code_prefix.search(code).group())
          except AttributeError as e:
            print(index, code)
            print(codes)
            raise e

      prefix = list(prefix_set)
      var_values = {}
      for pre in prefix:
        tmp_var_value = re.compile(pattern_var_value1.format(pre)).search(file_content)
        if tmp_var_value is None:
          continue

        tmp_var_value = tmp_var_value.group()

        try:
          tmp_var_value = pattern_var_value2.search(tmp_var_value).group()
        except AttributeError as e:
          print(pre, "************", tmp_var_value)
          raise e

        var_values = {**var_values, pre: tmp_var_value}

      parsed_codes = []
      for code in codes:
        const_valu = pattern_code_prefix.search(code)
        if "$" in code and const_valu is not None and const_valu.group() in var_values:
          parsed_codes = [
            *parsed_codes,
            code.replace("${" + const_valu.group() + "}",
                         var_values[const_valu.group()])
          ]

        else:
          parsed_codes = [*parsed_codes, code]

      tmp_df["codes"] = parsed_codes
      tmp_df["values"] = values
      tmp_df["file"] = file
      result_df = pd.concat([result_df, tmp_df], axis=0)
      print("文件{0}处理完毕".format(file))

# result_df = result_df[~result_df["codes"].str.contains("hzero.common")]
result_df.sort_values(by="codes", inplace=True)
result_df.drop_duplicates(subset="codes", keep="first", inplace=True)
result_df.reset_index(inplace=True, drop=True)

result_df.to_excel("intl.xlsx", index=False)

print(result_df)
