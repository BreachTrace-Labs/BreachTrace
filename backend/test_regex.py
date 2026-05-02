import re
pattern = re.compile(r"(?<![A-Za-z0-9/])(AKIA[0-9A-Z]{16})\b")
string = "AWS_ACCESS_KEY_ID=AKIAUDOTYKQPCWNJ4GXV"
print(pattern.findall(string))
