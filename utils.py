import uuid 
def allowed_file(filename: str, extensions) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in extensions
def make_stored_filename(original_filename: str) -> str:
    # strong unique name to avoid collisions, keep extension
    ext = original_filename.rsplit(".", 1)[1] if "." in original_filename else ""
    unique = uuid.uuid4().hex
    return f"{unique}.{ext}" if ext else unique
