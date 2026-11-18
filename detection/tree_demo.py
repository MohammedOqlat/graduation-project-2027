import ast

code = 'password = os.environ.get("PW")'
tree = ast.parse(code)
print(ast.dump(tree, indent=2))