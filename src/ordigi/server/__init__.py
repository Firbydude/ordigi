from fastapi import FastAPI

from ordigi.server.session import router as session_router

app = FastAPI()


app.include_router(session_router)
