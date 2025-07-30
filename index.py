from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Optional
import random
import string
from datetime import datetime, timedelta

app = FastAPI(title="OTP Verification API", description="Demo OTP verification system")

# CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        # "https://otp-api-v1.vercel.app"
        "https://apiauthv1api.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for demo (NOTE: not persistent on Vercel)
otp_store: Dict[str, Dict] = {}

class OTPRequest(BaseModel):
    phone_number: str

class OTPVerification(BaseModel):
    phone_number: str
    otp: str

class OTPResponse(BaseModel):
    message: str
    success: bool
    otp: Optional[str] = None  # For demo only

def generate_otp(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))

def is_otp_expired(created_time: datetime, expiry_minutes: int = 5) -> bool:
    return datetime.now() > created_time + timedelta(minutes=expiry_minutes)

@app.get("/")
async def root():
    return {"message": "OTP Verification API", "status": "active"}

# ⬇️ removed the leading "/api"
@app.post("/send-otp", response_model=OTPResponse)
async def send_otp(request: OTPRequest):
    try:
        phone_number = request.phone_number.strip()
        if not phone_number or len(phone_number) < 10:
            raise HTTPException(status_code=400, detail="Invalid phone number")
        otp = generate_otp()
        otp_store[phone_number] = {
            "otp": otp,
            "created_at": datetime.now(),
            "attempts": 0,
            "verified": False
        }
        return OTPResponse(
            message=f"OTP sent successfully to {phone_number}",
            success=True,
            otp=otp  # Remove in production
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send OTP: {str(e)}")

@app.post("/verify-otp", response_model=OTPResponse)
async def verify_otp(request: OTPVerification):
    try:
        phone_number = request.phone_number.strip()
        otp = request.otp.strip()

        if phone_number not in otp_store:
            raise HTTPException(status_code=404, detail="No OTP found for this phone number")

        stored_data = otp_store[phone_number]

        if is_otp_expired(stored_data["created_at"]):
            del otp_store[phone_number]
            raise HTTPException(status_code=410, detail="OTP has expired")

        if stored_data["attempts"] >= 3:
            del otp_store[phone_number]
            raise HTTPException(status_code=429, detail="Too many failed attempts")

        if stored_data["otp"] == otp:
            otp_store[phone_number]["verified"] = True
            return OTPResponse(message="OTP verified successfully!", success=True)
        else:
            otp_store[phone_number]["attempts"] += 1
            remaining_attempts = 3 - otp_store[phone_number]["attempts"]
            return OTPResponse(
                message=f"Invalid OTP. {remaining_attempts} attempts remaining.",
                success=False
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")

@app.get("/otp-status/{phone_number}")
async def get_otp_status(phone_number: str):
    if phone_number not in otp_store:
        return {"exists": False}
    data = otp_store[phone_number]
    return {
        "exists": True,
        "created_at": data["created_at"].isoformat(),
        "attempts": data["attempts"],
        "verified": data["verified"],
        "expired": is_otp_expired(data["created_at"])
    }

@app.delete("/clear-otp/{phone_number}")
async def clear_otp(phone_number: str):
    if phone_number in otp_store:
        del otp_store[phone_number]
        return {"message": "OTP cleared successfully"}
    return {"message": "No OTP found for this phone number"}

@app.get("/demo/all-otps")
async def get_all_otps():
    demo_data = {}
    for phone, data in otp_store.items():
        demo_data[phone] = {
            "otp": data["otp"],
            "created_at": data["created_at"].isoformat(),
            "attempts": data["attempts"],
            "verified": data["verified"],
            "expired": is_otp_expired(data["created_at"])
        }
    return demo_data

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
