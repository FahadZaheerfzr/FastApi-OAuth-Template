#model for open ai image generation
from pydantic import BaseModel

class User(BaseModel):
    id: str
    email: str
    password: str
    role: str
