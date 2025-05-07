from datetime import datetime
from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import get_jwt_identity, jwt_required
from app.config import Config
from app.models.user import User, UserSchema
from app.utils.logger import logger
from app.utils.validation import format_model_response
from app import db
from app.utils.llm_models import ModelHandler
from marshmallow import ValidationError
from app.utils.decorators import admin_required
from app.utils.error_handler import APIError


Analyze_ns = Namespace('Analyze', description='Analyze operations')

# Improved response models
plant_info_model = Analyze_ns.model('PlantInfo', {
    'is_plant_image': fields.Boolean(description='Whether the image contains a plant'),
    'image_quality': fields.String(description='Quality of the uploaded image')
})

diagnosis_model = Analyze_ns.model('Diagnosis', {
    'condition': fields.String(description='Identified plant condition'),
    'confidence': fields.String(description='Confidence level of diagnosis'),
    'description': fields.String(description='Description of the condition')
})

treatment_model = Analyze_ns.model('Treatment', {
    'recommendations': fields.List(fields.String, description='Treatment recommendations'),
    'prevention': fields.List(fields.String, description='Prevention measures')
})

user_guidance_model = Analyze_ns.model('UserGuidance', {
    'image_improvement': fields.String(description='Suggestions for better images'),
    'additional_info_needed': fields.String(description='Additional information needed')
})

metadata_model = Analyze_ns.model('RequestMetadata', {
    'timestamp': fields.String(description='Analysis timestamp'),
    'model_used': fields.String(description='AI model used for analysis'),
    'query_type': fields.String(description='Type of query (image, text, or combined)')
})

analysis_response_model = Analyze_ns.model('AnalysisResponse', {
    'plant_info': fields.Nested(plant_info_model),
    'diagnosis': fields.Nested(diagnosis_model),
    'treatment': fields.Nested(treatment_model),
    'user_guidance': fields.Nested(user_guidance_model),
    'request_metadata': fields.Nested(metadata_model)
})

# Request model
prediction_model = Analyze_ns.model('AnalyzeRequest', {
    'image': fields.String(required=False, description='Base64 encoded image string'),
    'symptoms': fields.String(required=False, description='Symptoms of the plant'),
    'model': fields.String(required=True, description='Model name (GPT-4 Vision, Gemini, Groq)'),
    'region': fields.String(required=True, description='Region of the plant'),
    'crop_type': fields.String(required=True, description='Crop type')
})

error_model = Analyze_ns.model('Error', {
    'status': fields.String(description='Error status'),
    'message': fields.String(description='Error message'),
    'status_code': fields.Integer(description='HTTP status code')
})

model_handler = ModelHandler({
    "OPENAI_API_KEY": Config.OPENAI_API_KEY,
    "GOOGLE_API_KEY": Config.GOOGLE_API_KEY,
    "GROQ_API_KEY": Config.GROQ_API_KEY
})

@Analyze_ns.route('/')
class Analyze(Resource):
    @Analyze_ns.doc(security='Bearer Auth')
    @jwt_required()
    @Analyze_ns.expect(prediction_model)
    @Analyze_ns.response(200, 'Analysis successful', analysis_response_model)
    @Analyze_ns.response(400, 'Validation error', error_model)
    @Analyze_ns.response(401, 'Unauthorized', error_model)
    @Analyze_ns.response(500, 'Server error', error_model)
    def post(self):
        """Analyze a plant image and return the prediction"""
        try:
            # Get current user
            current_user_id = get_jwt_identity()
            user = db.session.get(User, current_user_id)
            
            if not user:
                raise APIError('User not found', 404)
            
            data = Analyze_ns.payload
            image_data = data.get('image')
            symptoms = data.get('symptoms', '')
            model_choice = data.get('model', Config.GPT4_MODEL)
            region = data.get('region', 'Unknown')
            crop_type = data.get('crop_type', 'Unknown')

            # Validate inputs
            if not image_data and not symptoms:
                raise APIError('Either image or symptoms must be provided', 400)
                
            if model_choice not in ["GPT-4 Vision", "Gemini", "Groq"]:
                raise APIError('Unsupported model choice. Supported models are: GPT-4 Vision, Gemini, Groq', 400)
                
            # Determine query type
            query_type = "combined"
            if not image_data and symptoms:
                query_type = "text_only"
            elif image_data and not symptoms:
                query_type = "image_only"

            # Process and validate image if provided
            processed_image = None
            if image_data:
                try:
                    processed_image = model_handler.process_image(image_data)
                except Exception as e:
                    logger.error(f"Image processing error: {str(e)}")
                    raise APIError('Failed to process image', 500)

            # Model selection and analysis
            try:
                if model_choice == "GPT-4 Vision":
                    if query_type == "text_only":
                        result = model_handler.analyze_with_gpt4_text(symptoms, region, crop_type)
                    elif query_type == "image_only":
                        result = model_handler.analyze_with_gpt4_image(processed_image, region, crop_type)
                    else:
                        result = model_handler.analyze_with_gpt4(processed_image, symptoms, region, crop_type)
                elif model_choice == "Gemini":
                    if query_type == "text_only":
                        result = model_handler.analyze_with_gemini_text(symptoms, region, crop_type)
                    elif query_type == "image_only":
                        result = model_handler.analyze_with_gemini_image(processed_image, region, crop_type)
                    else:
                        result = model_handler.analyze_with_gemini(processed_image, symptoms, region, crop_type)
                elif model_choice == "Groq":
                    if query_type == "text_only":
                        result = model_handler.analyze_with_groq(symptoms, region, crop_type)
                    else:
                        raise APIError('Groq model only supports text-based analysis. Please provide a text description.', 400)

                # Format and validate response
                formatted_result = format_model_response(result)
                
                # Add request metadata
                formatted_result["request_metadata"] = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "model_used": model_choice,
                    "region": region,
                    "crop_type": crop_type,
                    "model_version": Config.get_model_config()[model_choice.lower().replace("-", "").replace(" ", "")]["model"],
                    "has_symptoms": bool(symptoms and symptoms.strip()),
                    "has_image": bool(image_data),
                    "query_type": query_type,
                    "image_quality": formatted_result["plant_info"].get("image_quality", "N/A"),
                    "is_plant_image": formatted_result["plant_info"].get("is_plant_image", True)
                }

                # Add user guidance based on the analysis
                if query_type == "image_only":
                    formatted_result["user_guidance"]["additional_info_needed"] = "Please provide any symptoms or observations you've noticed about the plant."
                elif query_type == "text_only":
                    formatted_result["user_guidance"]["image_improvement"] = "Consider uploading an image for more accurate analysis."
                else:
                    if not formatted_result["plant_info"]["is_plant_image"]:
                        formatted_result["user_guidance"]["image_improvement"] = "Please upload an image of a plant or leaf for better analysis."
                    elif formatted_result["plant_info"]["image_quality"] != "Good":
                        formatted_result["user_guidance"]["image_improvement"] = "Please try to take a clearer image of the plant or leaf."
                    if not symptoms or not symptoms.strip():
                        formatted_result["user_guidance"]["additional_info_needed"] = "Please provide any symptoms or observations you've noticed about the plant."

                return formatted_result, 200

            except Exception as e:
                logger.error(f"Analysis error: {str(e)}")
                raise APIError(f'Analysis failed: {str(e)}', 500)

        except APIError as e:
            return e.to_dict(), e.status_code
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            error = APIError('An unexpected error occurred', 500)
            return error.to_dict(), error.status_code


