# Cutica - Customer Ticket Automation

Cutica is an innovative platform designed to revolutionize how businesses handle customer service and support. Our mission is to streamline and enhance the customer support experience through state-of-the-art automation and intelligent solutions.

## Table of Contents

- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Environment Variables](#environment-variables)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features

- User authentication (Sign up, Login, Logout)
- Password reset via email
- Secure MongoDB integration
- Professional and responsive UI

## Technologies Used

- Flask - Micro web framework
- Flask-PyMongo - MongoDB integration
- Flask-Mail - Email sending
- Google Gmail API - Sending emails
- HTML/CSS - Frontend
- Jinja2 - Templating engine
- Python-dotenv - Environment variable management

## Installation

1. Clone the repository:

```bash
git clone https://github.com/your-username/cutica.git
cd cutica
```

2. Create a virtual environment and activate it:

```bash
python -m venv venv
source venv/bin/activate   # On Windows, use `venv\Scripts\activate`
```

3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

4. Place your `credentials.json` file for Google Gmail API in an `auth` folder.

5. Set up MongoDB Atlas and configure the connection URI.

## Environment Variables

Create a `.env` file in the root of the project and add the following variables:

```
MONGO_USERNAME=your_mongo_username
MONGO_PASSWORD=your_mongo_password
MAIL_USERNAME=your_gmail_username
MAIL_PASSWORD=your_gmail_password
SECRET_KEY=your_flask_secret_key
```

## Usage

1. Run the Flask application:

```bash
flask run
```

2. Open your browser and go to `http://127.0.0.1:5000/`

## Screenshots

### Main Home Page
![Main Home Page](https://github.com/your-username/cutica/screenshots/main_home.png)

### Login Page
![Login Page](https://github.com/your-username/cutica/screenshots/login.png)

### Sign Up Page
![Sign Up Page](https://github.com/your-username/cutica/screenshots/signup.png)

### Forgot Password Page
![Forgot Password Page](https://github.com/your-username/cutica/screenshots/forgot_password.png)

### Welcome Page
![Welcome Page](https://github.com/your-username/cutica/screenshots/home.png)

## Contributing

1. Fork the repository
2. Create a new branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

If you have any questions or suggestions, feel free to reach out:

- Email: vanirudhsharma@gmail.com
- LinkedIn: [Your LinkedIn](https://www.linkedin.com/in/v-s-s-anirudh-sharma)
- GitHub: [Your GitHub](https://github.com/showman-sharma)

---

Feel free to update the placeholder links and email addresses with your actual information. This README should provide a solid foundation for your project documentation.
