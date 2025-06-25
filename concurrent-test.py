import asyncio
import httpx
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

URL = "http://localhost:8080/sign/rsassa-pss?hashAlgorithm=sha256"
HEADERS = {
    "Content-Type": "text/plain",
    "Content-Encoding": "hex",
    "Accept": "application/x-pem-file",
}
BODY = "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f"

async def send_request(client, index):
    try:
        resp = await client.post(URL, content=BODY, headers=HEADERS)
        logging.info(f"Response {index}: {resp.status_code} - {resp.text[:100]!r}")
    except httpx.RequestError as e:
        logging.error(f"Request {index} failed: {e}")
    except Exception as e:
        logging.exception(f"Unexpected error on request {index}")

async def main():
    async with httpx.AsyncClient() as client:
        tasks = [send_request(client, i) for i in range(10)]  # 10 concurrent requests
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
