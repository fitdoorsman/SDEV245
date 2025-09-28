# fixed.py
from flask import jsonify, abort
from flask_login import login_required, current_user

@app.route('/account/<int:user_id>')
@login_required
def get_account(user_id: int):
    # Enforce ownership (allow admin override if you have roles)
    if current_user.id != user_id and not getattr(current_user, "is_admin", False):
        abort(403)

    user = db.query(User).filter_by(id=user_id).first()
    if not user:
        abort(404)

    return jsonify(user.to_dict())
