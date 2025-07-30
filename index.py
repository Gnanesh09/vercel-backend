from fastapi import FastAPI, HTTPException, Path
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Optional
import random
import string
from datetime import datetime, timedelta

app = FastAPI(title="OTP Verification API", description="Demo OTP verification system")

# CORS: Adjust origins to your frontend addresses
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://otp-auth-ten.vercel.app"        
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        # Add your deployed frontend URL if any
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage keyed by phone_number and device_id:
# Structure: {phone_number: {device_id: otp_data}}
otp_store: Dict[str, Dict[str, Dict]] = {}

class OTPRequest(BaseModel):
    phone_number: str
    device_id: Optional[str] = "default-device"  # Default device id if not provided

class OTPVerification(BaseModel):
    phone_number: str
    otp: str
    device_id: Optional[str] = "default-device"

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


@app.post("/send-otp", response_model=OTPResponse)
async def send_otp(request: OTPRequest):
    phone_number = request.phone_number.strip()
    device_id = request.device_id or "default-device"

    if not phone_number or len(phone_number) < 10:
        raise HTTPException(status_code=400, detail="Invalid phone number")

    if phone_number not in otp_store:
        otp_store[phone_number] = {}

    otp = generate_otp()
    otp_store[phone_number][device_id] = {
        "otp": otp,
        "created_at": datetime.now(),
        "attempts": 0,
        "verified": False
    }
    return OTPResponse(
        message=f"OTP sent successfully to {phone_number} (device: {device_id})",
        success=True,
        otp=otp  # Remove in production
    )


@app.post("/verify-otp", response_model=OTPResponse)
async def verify_otp(request: OTPVerification):
    phone_number = request.phone_number.strip()
    device_id = request.device_id or "default-device"
    otp = request.otp.strip()

    if phone_number not in otp_store or device_id not in otp_store[phone_number]:
        raise HTTPException(status_code=404, detail="No OTP found for this phone/device")

    stored_data = otp_store[phone_number][device_id]

    if is_otp_expired(stored_data["created_at"]):
        del otp_store[phone_number][device_id]
        if not otp_store[phone_number]:
            del otp_store[phone_number]
        raise HTTPException(status_code=410, detail="OTP has expired")

    if stored_data["attempts"] >= 3:
        del otp_store[phone_number][device_id]
        if not otp_store[phone_number]:
            del otp_store[phone_number]
        raise HTTPException(status_code=429, detail="Too many failed attempts")

    if stored_data["otp"] == otp:
        otp_store[phone_number][device_id]["verified"] = True
        return OTPResponse(message="OTP verified successfully!", success=True)
    else:
        otp_store[phone_number][device_id]["attempts"] += 1
        remaining_attempts = 3 - otp_store[phone_number][device_id]["attempts"]
        return OTPResponse(
            message=f"Invalid OTP. {remaining_attempts} attempts remaining.",
            success=False
        )


@app.delete("/clear-otp/{phone_number}/{device_id}")
async def clear_otp(
    phone_number: str = Path(..., description="Phone number"),
    device_id: Optional[str] = Path("default-device", description="Device ID"),
):
    phone_number = phone_number.strip()
    device_id = device_id or "default-device"
    if phone_number in otp_store and device_id in otp_store[phone_number]:
        del otp_store[phone_number][device_id]
        if not otp_store[phone_number]:
            del otp_store[phone_number]
        return {"message": f"OTP cleared for {phone_number} device {device_id}"}
    return {"message": f"No OTP found for {phone_number} device {device_id}"}


@app.get("/demo/all-otps")
async def get_all_otps():
    demo_data = {}
    for phone, devices in otp_store.items():
        demo_data[phone] = {}
        for device_id, data in devices.items():
            demo_data[phone][device_id] = {
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
