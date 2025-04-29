from dotenv import load_dotenv
import logging as log
import openai
import os

load_dotenv()
openai.api_key = os.getenv("openai_token")


def main():
    try:
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Who invented TCP/IP?"}],
        )
        log.info("API call succeeded!")
        log.debug(f"Returned response object: {response}")
        log.debug(f"Returned message: {response.choices[0].message.content}")
    except Exception as e:
        log.error(e)

    log.debug("Done!")


if __name__ == "__main__":
    log.basicConfig(
        datefmt="%Y-%m-%d %H:%M:%S",
        format="%(levelname)s;%(asctime)s;%(message)s",
        level=log.DEBUG,
    )
    main()
