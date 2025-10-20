import os
from . import scanner, parser, patcher, builder, comparer
from .utils import read_json, write_json

def main():
    dockerfile_path = "Dockerfile"
    image_name = "myapp:test"

    # Read Dockerfile
    with open(dockerfile_path, "r") as f:
        docker_text = f.read()

    # 1. Scan before
    builder.build_image(".", image_name, dockerfile_path)
    before = scanner.scan_image(image_name)
    before_summary = parser.summarize(before)
    print("Before:", before_summary)

    # 2. Patch
    base_name, _ = patcher.find_base_image(docker_text)
    proposed = patcher.propose_upgrade(base_name)
    if proposed:
        docker_text = patcher.replace_base_image(docker_text, proposed)
        print(f"Base image upgraded to: {proposed}")
    docker_text = patcher.add_apt_upgrade(docker_text)

    # Save patched file
    patched_path = "Dockerfile.patched"
    with open(patched_path, "w") as f:
        f.write(docker_text)

    # 3. Rebuild + Rescan
    patched_image = f"{image_name}-patched"
    builder.build_image(".", patched_image, patched_path)
    after = scanner.scan_image(patched_image)
    after_summary = parser.summarize(after)
    print("After:", after_summary)

    # 4. Compare
    comparison = comparer.compare(before_summary, after_summary)
    print("Comparison:", comparison)

    # Save results
    write_json("trivy_before.json", before)
    write_json("trivy_after.json", after)

if __name__ == "__main__":
    main()
