# PodClub Backend

## Overview

PodClub is a community-driven platform where users can connect, share, and discover podcasts. This repository contains the backend code for the PodClub application, built using Flask, SQLAlchemy, and other relevant Python libraries.

## Setup and Installation

### Prerequisites

- Python 3.8 or higher
- Virtual environment (optional but recommended)
- SQLite (for the development database)

### Installation

1. **Clone the repository:**
   git clone https://github.com/Jeremy-3/PodClub-Backend.git
   cd podclub-backend
### Create and activate a virtual environment:
python3 -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
### Install dependencies:
pip install -r requirements.txt
### Set up the database:
flask db init
flask db migrate
flask db upgrade
### Seed the database with initial data:
python seed.py
### Running the Application
#### Start the Flask server:
flask run
### Access the application: 
Open your web browser and go to http://127.0.0.1:5000.

### Project Structure
PodClub-Backend/
├── app/
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   ├── ...
├── migrations/
├── seed.py
├── requirements.txt
└── README.md
- app/: Contains the application modules including initialization, models, and routes.

- migrations/: Contains database migration files managed by Flask-Migrate.

- seed.py: Script to seed the database with initial data.

- requirements.txt: List of Python dependencies.

- README.md: This file.

## Models
### User
Represents a user in the system.

- id: Integer, primary key.

- username: String, unique, required.

- email: String, unique, required.

- password_hash: String, required.

- role: String, required (e.g., 'user', 'admin').

- is_banned: Boolean, default is False.

- created_at: DateTime, default is current timestamp.

### Report
Represents a report made by a user against another user.

- id: Integer, primary key.

- user_id: Integer, foreign key referencing users.id, required.

- reported_user_id: Integer, foreign key referencing users.id, required.

- reason: String, required, at least 10 characters.

- created_at: DateTime, default is current timestamp.

### Channel
Represents a discussion channel.

- id: Integer, primary key.

- name: String, required.

- description: String.

- created_at: DateTime, default is current timestamp.

- owner_id: Integer, foreign key referencing users.id, required.

### Message
Represents a message sent in a channel.

- id: Integer, primary key.

- content: String, required.

- sender_id: Integer, foreign key referencing users.id, required.

- channel_id: Integer, foreign key referencing channels.id, required.

- created_at: DateTime, default is current timestamp.

### API Endpoints
#### User Endpoints
- POST /users: Create a new user.

- GET /users/<id>: Retrieve a user by ID.

- PUT /users/<id>: Update a user's information.

- DELETE /users/<id>: Delete a user.

### Channel Endpoints
- POST /channels: Create a new channel.

- GET /channels/<id>: Retrieve a channel by ID.

- PUT /channels/<id>: Update a channel's information.

- DELETE /channels/<id>: Delete a channel.

### Message Endpoints
- POST /messages: Create a new message.

- GET /messages/<id>: Retrieve a message by ID.

- PUT /messages/<id>: Update a message's content.

- DELETE /messages/<id>: Delete a message.

### Report Endpoints
- POST /reports: Create a new report.

- GET /reports/<id>: Retrieve a report by ID.

- PUT /reports/<id>: Update a report's information.

- DELETE /reports/<id>: Delete a report.

### Contribution Guidelines
1. Fork the repository.

2. Create a new branch (git checkout -b feature-branch).

3. Make your changes.

4. Commit your changes (git commit -m 'Add new feature').

5. Push to the branch (git push origin feature-branch).

6. Open a pull request.

### License
licensed by MIT 