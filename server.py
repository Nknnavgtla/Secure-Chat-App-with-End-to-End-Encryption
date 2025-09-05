from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
import json

app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = 'dev-secret'  # for demo only
socketio = SocketIO(app, cors_allowed_origins="*")

# --- Simple SQLite storage for public keys and logs ---
engine = create_engine('sqlite:///chat_store.db', connect_args={'check_same_thread': False})
Base = declarative_base()

class PublicKey(Base):
    __tablename__ = 'public_keys'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    # store base64 or PEM of public key (SPKI)
    public_key = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow)

class MessageLog(Base):
    __tablename__ = 'message_logs'
    id = Column(Integer, primary_key=True)
    sender = Column(String, nullable=False)
    recipient = Column(String, nullable=False)
    payload_json = Column(Text, nullable=False)  # JSON string with ciphertext, encryptedKey, iv, etc.
    ts = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
db = Session()

# --- Routes ---
@app.route('/')
def index():
    return send_from_directory('static', 'client.html')

@app.route('/api/pubkey', methods=['POST'])
def upload_pubkey():
    """
    Body JSON: { "username": "alice", "publicKey": "<base64-encoded-SPKI-or-PEM>" }
    """
    data = request.get_json()
    if not data or 'username' not in data or 'publicKey' not in data:
        return jsonify({'error': 'bad request'}), 400
    username = data['username']
    pub = data['publicKey']
    pk = db.query(PublicKey).filter_by(username=username).first()
    if pk:
        pk.public_key = pub
        pk.updated_at = datetime.utcnow()
    else:
        pk = PublicKey(username=username, public_key=pub)
        db.add(pk)
    db.commit()
    return jsonify({'ok': True})

@app.route('/api/pubkey/<username>', methods=['GET'])
def get_pubkey(username):
    pk = db.query(PublicKey).filter_by(username=username).first()
    if not pk:
        return jsonify({'found': False}), 404
    return jsonify({'found': True, 'publicKey': pk.public_key})

# --- Socket.IO events ---
@socketio.on('join')
def on_join(data):
    # join a room for the username so we can emit directly
    username = data.get('username')
    if username:
        join_room(username)
        emit('status', {'msg': f'{username} joined'}, room=username)

@socketio.on('encrypted_message')
def on_encrypted_message(data):
    """
    data expected:
    {
      "sender": "alice",
      "recipient": "bob",
      "ciphertext": "<base64>",
      "encryptedKey": "<base64>",
      "iv": "<base64>"
      // any additional metadata allowed
    }
    """
    # Validate minimal fields
    sender = data.get('sender')
    recipient = data.get('recipient')
    if not sender or not recipient or 'ciphertext' not in data or 'encryptedKey' not in data:
        emit('error', {'reason': 'invalid message format'})
        return

    # Store encrypted payload in DB (server can't read it)
    payload = {
        'ciphertext': data['ciphertext'],
        'encryptedKey': data['encryptedKey'],
        'iv': data.get('iv'),
        'sender': sender,
        'ts': datetime.utcnow().isoformat()
    }
    log = MessageLog(sender=sender, recipient=recipient, payload_json=json.dumps(payload))
    db.add(log)
    db.commit()

    # Emit to recipient room
    socketio.emit('incoming_encrypted_message', payload, room=recipient)

    # Optionally echo confirm to sender
    emit('sent', {'ok': True})

# Endpoint to fetch encrypted logs for a user (they remain encrypted)
@app.route('/api/logs/<username>', methods=['GET'])
def fetch_logs(username):
    # return messages where user is recipient or sender
    rows = db.query(MessageLog).filter((MessageLog.sender == username) | (MessageLog.recipient == username)).order_by(MessageLog.ts).all()
    out = []
    for r in rows:
        out.append({
            'id': r.id,
            'sender': r.sender,
            'recipient': r.recipient,
            'payload': json.loads(r.payload_json),
            'ts': r.ts.isoformat()
        })
    return jsonify(out)

if __name__ == '__main__':
    # for local testing, eventlet is convenient
    socketio.run(app, host='0.0.0.0', port=5000)
