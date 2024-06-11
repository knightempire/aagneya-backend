# Aagenya Sports Club Backend

This repository contains the backend code for the Aagenya Sports Club, developed for Amrita University. The backend is built using Node.js and MySQL, providing a robust and scalable solution for managing the club's activities, members, events, and other related functionalities.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Database Setup](#database-setup)
- [Running the Application](#running-the-application)
- [API Documentation](#api-documentation)
- [Contributing](#contributing)
- [License](#license)

## Installation

To set up the project locally, follow these steps:

1. **Clone the repository:**
    ```bash
    git clone https://github.com/knightempire/aagneya-backend.git
    ```

2. **Install dependencies:**
    Make sure you have Node.js and npm installed. Then run:
    ```bash
    npm install
    ```

## Configuration

Create a `.env` file in the root directory of the project and add the following environment variables:

```env
DB_HOST=your-database-host
DB_USER=your-database-username
DB_PASSWORD=your-database-password
DB_NAME=your-database-name
PORT=your-port
JWT_SECRET=your-jwt-secret
