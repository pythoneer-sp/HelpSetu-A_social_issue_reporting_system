# HelpSetu Documentation

This reporting system is a Flask-based web application designed to allow users to report various social issues and incidents. This document provides an overview of the system's functionality and how to use it.

## Getting Started

**Installation**: Ensure you have Python installed on your system. Then activate your virtual environment

```
python -m venv venv
```

Then You can install the required dependencies using `pip`:

```
pip install -r requirements.txt
```

**Setting Up the Database**: The Database automatically sets up when you run `app.py`

**Running the Application**: Start the Flask application by running the following command in your terminal:

`python app.py`

**Accessing the Application**: Once the application is running, you can access it by opening a web browser and navigating to `http://localhost:5000`.

## Functionality

### Reporting Issues

Users can report issues by sending a POST request to the `/sendus` endpoint from a form. They need to provide details such as their name, victim's name, contact information, address, state, district, block, and proof of incidents.Upload location button track your location and store in database. The issue is stored in the database upon successful reporting, and an email notification is sent.
See `functions.py` for input field names.

### User Registration

New users can create their account by sending a POST request to the `/create_account` endpoint with their mobile number which will verify through OTP and setting the password.

### User Login

Registered users can log in by sending a POST request to the `/login` endpoint with their registered mobile number and password. If the credentials are valid, the user is logged in.

### Rewards

The `/rewards` endpoint provides the earned coins of users which can be earned by sending report. This allows users to view the reward page and see the coins earned by each user.

## Endpoints

- **POST `/sendus`**: Report an issue.
- **POST `/create_account`**: Register a new user.
- **POST `/login`**: Log in as an existing user.
- **GET `/rewards`**: View the reward page.
- **`/partners`**: View the partners of HelpSetu
- **`/About Us`**: To know about us
- **`/Donate Us`**: To donate us in our initiative

## Dependencies

See `requirements.txt`

## Running the Application

To run the application, execute the `app.py` file using Python. Make sure to set up the database before running the application.
