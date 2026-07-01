import sys

file_path = 'templates/Part_time_employee.html'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace DOMContentLoaded with IIFE
content = content.replace("document.addEventListener('DOMContentLoaded', () => {", "(() => {")
content = content.replace("document.addEventListener('DOMContentLoaded', function() {", "(function() {")

# Write it back
with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Patched!")
