import base64
from datetime import datetime
import io
from typing import Dict, Any
from PIL import Image
from app.utils.logger import logger
from app.config import Config


def validate_image(image_data: str) -> Dict[str, Any]:
    """Validate and process image data."""
    try:
        if not image_data:
            raise ValueError("No image data provided. Please upload an image of the plant or leaf you want to analyze.")
            
        if not isinstance(image_data, str):
            raise ValueError("Image data must be a string. Please ensure you're uploading the image correctly.")
            
        if not image_data.startswith("data:image"):
            raise ValueError("Invalid image data format. Please upload a valid image file.")
            
        # Extract image format and base64 data
        format_info = image_data.split(";")[0].split("/")[1]
        if format_info not in Config.SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported image format: {format_info}. Please upload an image in one of these formats: {', '.join(Config.SUPPORTED_FORMATS)}")
            
        # Extract base64 data
        base64_data = image_data.split(",")[1]
        
        # Decode and validate image
        try:
            image_bytes = base64.b64decode(base64_data)
            image = Image.open(io.BytesIO(image_bytes))
            image.verify()  # Verify image integrity
            image.close()
        except Exception as e:
            raise ValueError(f"Invalid or corrupted image: {str(e)}. Please try uploading a different image.")
            
        return {
            "bytes": image_bytes,
            "base64": base64_data,
            "format": format_info
        }
    except ValueError as e:
        raise e
    except Exception as e:
        logger.error(f"Image validation error: {str(e)}")
        raise ValueError(f"Failed to validate image: {str(e)}")


def format_response(data: Dict[str, Any], status: int = 200) -> Dict[str, Any]:
    """Format API response."""
    try:
        # Add status information
        response = {
            "status": "success" if status == 200 else "error",
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add metadata if not present
        if "metadata" not in data:
            data["metadata"] = {
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "model_version": "1.0"
            }
        
        return response
    except Exception as e:
        logger.error(f"Response formatting error: {str(e)}")
        return {
            "status": "error",
            "error": {
                "message": "Failed to format response",
                "type": "ResponseError",
                "suggestion": "Please try again"
            },
            "timestamp": datetime.utcnow().isoformat()
        }


def format_error_response(error_message: str, status_code: int = 400) -> Dict[str, Any]:
    """Format error response."""
    try:
        # Provide more user-friendly error messages
        if "No image data provided" in error_message:
            error_message = "Please upload an image of the plant or leaf you want to analyze."
        elif "Invalid image data format" in error_message:
            error_message = "The uploaded image format is not valid. Please try uploading a different image."
        elif "Unsupported image format" in error_message:
            error_message = f"The image format is not supported. Please upload an image in one of these formats: {', '.join(Config.SUPPORTED_FORMATS)}"
        elif "Invalid or corrupted image" in error_message:
            error_message = "The uploaded image appears to be corrupted. Please try uploading a different image."
        elif "Please provide either an image or a description" in error_message:
            error_message = "Please provide either an image of the plant or a description of what you'd like to know."
        elif "Missing required field" in error_message:
            error_message = "The analysis response is incomplete. Please try again."
        elif "Groq model only supports text-based analysis" in error_message:
            error_message = "The Groq model can only analyze text descriptions. Please provide a text description or choose a different model."
        
        # Add helpful suggestions based on the error
        suggestion = "Please try again with a valid image or description."
        if "No image data provided" in error_message:
            suggestion = "You can either upload an image or provide a text description of the plant/symptoms."
        elif "No symptoms provided" in error_message:
            suggestion = "Consider adding any symptoms or observations you've noticed about the plant."
        elif "Invalid image" in error_message:
            suggestion = "Try uploading a different image or provide a text description instead."
        elif "Groq model" in error_message:
            suggestion = "Try using GPT-4 Vision or Gemini model for image analysis, or provide a text description for Groq."
        
        return {
            "status": "error",
            "error": {
                "message": error_message,
                "type": "ValidationError" if status_code == 400 else "ProcessingError",
                "suggestion": suggestion
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error formatting error response: {str(e)}")
        return {
            "status": "error",
            "error": {
                "message": "An unexpected error occurred",
                "type": "SystemError",
                "suggestion": "Please try again later"
            },
            "timestamp": datetime.utcnow().isoformat()
        }


def validate_request_data(data: Dict[str, Any]) -> None:
    """Validate request data."""
    # Check if either image or symptoms are provided
    if not data.get("image") and not data.get("symptoms"):
        raise ValueError("Please provide either an image or a description of the plant/symptoms.")
    
    # Check if image is provided and valid
    if "image" in data and data["image"]:
        try:
            validate_image(data["image"])
        except ValueError as e:
            raise ValueError(f"Invalid image: {str(e)}")
    
    # Check if symptoms are provided
    if "symptoms" in data and not data["symptoms"].strip():
        logger.warning("No symptoms provided. Analysis will be based on image only.")
    
    # Validate region and crop_type if provided
    if "region" in data and not data["region"].strip():
        logger.warning("Region not provided. Using 'Unknown' as default.")
        data["region"] = "Unknown"
    
    if "crop_type" in data and not data["crop_type"].strip():
        logger.warning("Crop type not provided. Using 'Unknown' as default.")
        data["crop_type"] = "Unknown"


def calculate_confidence_score(plant_confidence: float, disease_confidence: float) -> float:
    """Calculate overall confidence score."""
    try:
        # Weight the confidences (plant identification is more important)
        return (plant_confidence * 0.6) + (disease_confidence * 0.4)
    except Exception as e:
        logger.error(f"Confidence calculation error: {str(e)}")
        return 0.0


def format_model_response(response: Dict[str, Any]) -> Dict[str, Any]:
    """Format and validate model response."""
    try:
        # Validate required fields
        required_fields = ["plant_info", "disease_info", "treatment", "prevention", "additional_info", "user_guidance"]
        for field in required_fields:
            if field not in response:
                raise ValueError(f"Missing required field in model response: {field}")
        
        # Validate plant_info fields
        if "is_plant_image" not in response["plant_info"]:
            response["plant_info"]["is_plant_image"] = True
        
        if "image_quality" not in response["plant_info"]:
            response["plant_info"]["image_quality"] = "Good"
        
        if "image_feedback" not in response["plant_info"]:
            response["plant_info"]["image_feedback"] = "Image appears to be of a plant or leaf."
        
        # Validate disease_info fields
        if "analysis_type" not in response["disease_info"]:
            response["disease_info"]["analysis_type"] = "Image-based"
        
        # Validate query_type and intent
        if "query_type" not in response:
            response["query_type"] = "combined"
        
        if "query_intent" not in response:
            response["query_intent"] = "Disease detection"
        
        if "response_focus" not in response:
            response["response_focus"] = "Plant disease analysis"
        
        # Format confidence scores as percentages
        if "confidence" in response["plant_info"]:
            response["plant_info"]["confidence"] = float(response["plant_info"]["confidence"])
        
        if "confidence" in response["disease_info"]:
            response["disease_info"]["confidence"] = float(response["disease_info"]["confidence"])
        
        # Ensure list fields are actually lists
        list_fields = ["recommendations", "prevention_tips", "additional_resources"]
        for field in list_fields:
            if field in response["treatment"] and not isinstance(response["treatment"][field], list):
                response["treatment"][field] = [response["treatment"][field]]
            if field in response["prevention"] and not isinstance(response["prevention"][field], list):
                response["prevention"][field] = [response["prevention"][field]]
            if field in response["additional_info"] and not isinstance(response["additional_info"][field], list):
                response["additional_info"][field] = [response["additional_info"][field]]
            if field in response["user_guidance"] and not isinstance(response["user_guidance"][field], list):
                response["user_guidance"][field] = [response["user_guidance"][field]]
        
        # Add metadata
        response["metadata"] = {
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "model_version": "1.0",
            "confidence_score": calculate_confidence_score(
                float(response["plant_info"].get("confidence", 0)),
                float(response["disease_info"].get("confidence", 0))
            )
        }
        
        return response
        
    except Exception as e:
        logger.error(f"Response formatting error: {str(e)}")
        raise 
