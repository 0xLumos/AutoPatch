import logging
import time
from typing import List
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

MAX_PAGES = 100
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
INITIAL_BACKOFF = 1


def _create_session_with_retries() -> requests.Session:
    """Create a requests session with retry strategy for rate limits and 5xx errors."""
    session = requests.Session()
    retry_strategy = Retry(
        total=MAX_RETRIES,
        backoff_factor=INITIAL_BACKOFF,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def fetch_top_images(count: int = 400) -> List[str]:
    """
    Fetch top Docker Hub library images with robust error handling.

    Args:
        count: Number of images to fetch (default 400)

    Returns:
        List of image names in format "name:latest". Returns partial results
        if fetching fails partway through.
    """
    images: List[str] = []
    page = 1
    session = _create_session_with_retries()

    try:
        while len(images) < count and page <= MAX_PAGES:
            url = f"https://hub.docker.com/v2/repositories/library/?page_size=100&page={page}"

            try:
                logger.info(f"Fetching page {page} from Docker Hub...")
                response = session.get(url, timeout=REQUEST_TIMEOUT)
                response.raise_for_status()

            except requests.exceptions.Timeout:
                logger.error(f"Timeout while fetching page {page}. Stopping fetch.")
                break

            except requests.exceptions.HTTPError as e:
                if response.status_code == 429:
                    logger.warning(
                        f"Rate limited (429) on page {page}. Exponential backoff "
                        f"already attempted by requests library."
                    )
                    break
                elif 500 <= response.status_code < 600:
                    logger.error(
                        f"Server error ({response.status_code}) on page {page}. "
                        f"Stopping fetch."
                    )
                    break
                else:
                    logger.error(f"HTTP error {response.status_code} on page {page}.")
                    break

            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed on page {page}: {e}. Stopping fetch.")
                break

            except Exception as e:
                logger.error(f"Unexpected error parsing page {page}: {e}")
                break

            try:
                data = response.json()
            except ValueError as e:
                logger.error(f"Failed to parse JSON on page {page}: {e}")
                break

            # Safety check: ensure required fields exist
            if "results" not in data:
                logger.error(f"Unexpected API response format on page {page}")
                break

            # Extract image names
            try:
                for repo in data["results"]:
                    if "name" in repo:
                        name = repo["name"]
                        images.append(f"{name}:latest")
                        if len(images) >= count:
                            break

            except (KeyError, TypeError) as e:
                logger.error(f"Error parsing repository data on page {page}: {e}")
                break

            # Check for next page
            if not data.get("next"):
                logger.info("Reached end of Docker Hub library results")
                break

            page += 1
            time.sleep(0.1)  # Small delay between requests to be respectful

    finally:
        session.close()

    logger.info(f"Fetched {len(images)} images (requested {count})")
    return images


if __name__ == "__main__":
    try:
        imgs = fetch_top_images(400)

        if not imgs:
            logger.warning("No images fetched. File will be empty.")

        with open("image_list.txt", "w") as f:
            for img in imgs:
                f.write(img + "\n")

        logger.info(f"Saved {len(imgs)} images to image_list.txt")
        print(f"[+] Saved {len(imgs)} images to image_list.txt")

    except IOError as e:
        logger.error(f"Failed to write image_list.txt: {e}")
        print(f"[-] Error writing to file: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}")
        print(f"[-] Unexpected error: {e}")
