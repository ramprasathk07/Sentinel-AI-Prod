import uvicorn
from api.main import app
from utils.logger import logger

if __name__ == "__main__":
    logger.info("Starting Sentinel-AI on port 8005...")
    try:
        uvicorn.run(app, host="0.0.0.0", port=8005, log_level="info")
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
