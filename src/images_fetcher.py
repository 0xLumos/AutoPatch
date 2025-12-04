import requests

def fetch_top_images(count=400):
    images = []
    page = 1

    while len(images) < count:
        url = f"https://hub.docker.com/v2/repositories/library/?page_size=100&page={page}"
        r = requests.get(url)
        data = r.json()

        for repo in data["results"]:
            name = repo["name"]
            images.append(f"{name}:latest")
            if len(images) >= count:
                break

        if not data["next"]:
            break

        page += 1

    return images

if __name__ == "__main__":
    imgs = fetch_top_images(400)
    with open("image_list.txt", "w") as f:
        for i in imgs:
            f.write(i + "\n")

    print(f"[+] Saved {len(imgs)} images to image_list.txt")

