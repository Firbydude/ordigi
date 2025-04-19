import asyncio

import uvicorn
from fastapi import FastAPI

from ordigi.server.session import router as session_router

app = FastAPI()


app.include_router(session_router)


async def main():
    config = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
