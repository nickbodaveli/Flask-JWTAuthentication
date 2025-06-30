from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required,
    get_jwt, current_user, get_jwt_identity
)
from models import User, TokenBlocklist
from marshmallow import Schema, fields

# User Schema
class UserSchema(Schema):
    id = fields.String()
    username = fields.String()
    email = fields.String()

def register_routes(app, db, jwt):

    ### JWT Loaders ###
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_headers, jwt_data):
        identity = jwt_data["sub"]
        return User.query.filter_by(username=identity).first()

    @jwt.additional_claims_loader
    def make_additional_claims(identity):
        return {"is_staff": identity == "janedoe123"}

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_data):
        return jsonify({"message": "Token has expired", "error": "token_expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({"message": "Invalid token", "error": "invalid_token"}), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({"message": "Missing token", "error": "authorization_header"}), 401

    @jwt.token_in_blocklist_loader
    def token_in_blocklist_callback(jwt_header, jwt_data):
        jti = jwt_data["jti"]
        token = db.session.query(TokenBlocklist).filter_by(jti=jti).first()
        return token is not None


    ### AUTH ROUTES ###
    @app.route("/auth/register", methods=["POST"])
    def register_user():
        data = request.get_json()
        if User.get_user_by_username(data.get("username")):
            return jsonify({"error": "User already exists"}), 409
        new_user = User(username=data.get("username"), email=data.get("email"))
        new_user.set_password(data.get("password"))
        new_user.save()
        return jsonify({"message": "User created"}), 201

    @app.route("/auth/login", methods=["POST"])
    def login_user():
        data = request.get_json()
        user = User.get_user_by_username(data.get("username"))
        if user and user.check_password(data.get("password")):
            access = create_access_token(identity=user.username)
            refresh = create_refresh_token(identity=user.username)
            return jsonify({
                "message": "Logged In",
                "tokens": {"access": access, "refresh": refresh}
            }), 200
        return jsonify({"error": "Invalid credentials"}), 400

    @app.route("/auth/whoami", methods=["GET"])
    @jwt_required()
    def whoami():
        return jsonify({
            "username": current_user.username,
            "email": current_user.email
        })

    @app.route("/auth/refresh", methods=["GET"])
    @jwt_required(refresh=True)
    def refresh_access():
        identity = get_jwt_identity()
        access_token = create_access_token(identity=identity)
        return jsonify({"access_token": access_token})

    @app.route("/auth/logout", methods=["GET"])
    @jwt_required(verify_type=False)
    def logout_user():
        jwt_data = get_jwt()
        token_b = TokenBlocklist(jti=jwt_data["jti"])
        token_b.save()
        return jsonify({"message": f"{jwt_data['type']} token revoked"}), 200


    ### USER ROUTES ###
    @app.route("/users/all", methods=["GET"])
    @jwt_required()
    def get_all_users():
        claims = get_jwt()
        if not claims.get("is_staff"):
            return jsonify({"message": "Unauthorized"}), 401

        page = request.args.get("page", default=1, type=int)
        per_page = request.args.get("per_page", default=3, type=int)

        users = User.query.paginate(page=page, per_page=per_page)
        result = UserSchema(many=True).dump(users.items)

        return jsonify({"users": result})
