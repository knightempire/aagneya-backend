const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');



const app = express();
const port = 3000 || null;


app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

require('dotenv').config();
const {
    DB_HOST,
    DB_USER,
    DB_PASSWORD,
    DB_DATABASE,
    DB_WAIT_FOR_CONNECTIONS,
    DB_CONNECTION_LIMIT,
    DB_QUEUE_LIMIT,
    SESSION_SECRET,
    JWT_SECRET,
    JWT_EXPIRY,
} = process.env;

const dbConfig = {
    host: DB_HOST,
    // port: 10379,
    port: 3306,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_DATABASE,
    waitForConnections: DB_WAIT_FOR_CONNECTIONS === 'true', // Convert string to boolean
    connectionLimit: parseInt(DB_CONNECTION_LIMIT, 10),
    queueLimit: parseInt(DB_QUEUE_LIMIT, 10),
};



// Create a MySQL pool
const pool = mysql.createPool(dbConfig);

// Serve uploaded images statically
app.use('/uploads', express.static('./uploads'));



// Multer middleware setup
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, 'uploads');
    },
    filename: function(req, file, cb) {
        cb(null, 'img_' + Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    fileFilter: function(req, file, cb) {
        // Check if the file is an image
        if (!file.mimetype.startsWith('image/')) {
            return cb(new Error('Only images are allowed.'));
        }
        cb(null, true);
    }
});

// Session middleware configuration
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));

(async() => {
    try {
        // Attempt to get a connection from the pool
        const connection = await pool.getConnection();

        // If connection successful, log a success message
        console.log('Database connected successfully');

        // Release the connection back to the pool
        connection.release();
    } catch (error) {
        // Log an error message if connection fails
        console.error('Error connecting to the database:', error);
        process.exit(1); // Terminate the application process
    }
})();




//function to create token
const createtoken = (req, res, rows) => {
    // Assuming rows contain user data with a username field
    const username = rows[0].username;

    // Sign the token with the username instead of email
    const token = jwt.sign({ username: username }, JWT_SECRET, {


        expiresIn: JWT_EXPIRY,
    });

    // Assuming you are using Express and want to store the token in the session
    req.session.jwtToken = token;

    // Return the token
    return token;
};





//function to verify token
// Middleware to authenticate token and retrieve user data
// async function getUserDataByUsername(username) {
//     try {
//         // Query the database to find the user by username
//         const user = await User.findOne({ username });

//         // If user is found, return user data
//         if (user) {
//             return {
//                 id: user.id,
//                 username: user.username,
//                 email: user.email,
//                 // Add other user data properties as needed
//             };
//         } else {
//             return null; // Return null if user is not found
//         }
//     } catch (error) {
//         console.error('Error fetching user data:', error.message);
//         throw error; // Throw error for handling in the calling code
//     }
// }

const authenticateToken = async(req, res, next) => {
    try {
        // Check if Authorization header exists
        if (!req.headers.authorization) {
            return res.status(401).json({ error: 'Unauthorized' }); // Return 401 Unauthorized status
        }

        // Retrieve token from request headers and split it
        const token = req.headers.authorization.split(' ')[1];
        console.log("Token:", token); // Print token value

        // Verify token
        jwt.verify(token, "aagenya@1234", async(err, decodedToken) => {
            if (err) {
                console.error('Authentication error:', err.message);
                // Token is invalid or expired, send 401 Unauthorized response to client
                return res.status(401).json({ error: 'Unauthorized' });
            } else {
                console.log('Decoded Token:', decodedToken); // Print decoded token data

                // Decode the token to get the username
                const username = decodedToken.username;
                console.log(username)

                // Retrieve user data from the database based on the username
                const userData = await getUserDataByUsername(username);

                if (!userData) {
                    // User not found in the database, send 401 Unauthorized response
                    console.error('User not found');
                    return res.status(401).json({ error: 'Unauthorized' });
                }

                // Set user information in request object
                req.user = userData;
                next(); // Proceed to next middleware
            }
        });
    } catch (err) {
        console.error('Error in authentication middleware:', err.message);
        res.status(500).send('Internal Server Error');
    }
};




//decoding the token
app.post('/api/decodeToken', async(req, res) => {
    console.log('api decode requested');
    try {
        // Extract the token from the request body
        const { token } = req.body;

        console.log(token)

        // Verify and decode the token
        const decodedToken = jwt.verify(token, JWT_SECRET);
        // console.log(decodedToken)

        // Extract username from decoded token
        const { username } = decodedToken;

        // Get a connection from the pool
        const connection = await pool.getConnection();

        try {
            // Query the database to retrieve user data based on username
            const [rows] = await connection.execute('SELECT user_id,name,username FROM users WHERE username = ?', [username]);

            // Check if user exists in the database
            if (rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Get the user data from the query results
            const userData = rows[0];
            console.log('decoded token');

            // Send user data back to the client
            res.status(200).json(userData);
        } catch (error) {
            console.error('Error querying database:', error.message);
            res.status(500).json({ error: 'Internal server error' });
        } finally {
            // Release the connection back to the pool
            connection.release();
        }
    } catch (error) {
        // Handle any errors, such as token validation failure
        console.error('Error decoding token:', error.message);
        res.status(400).json({ error: 'Failed to decode token' });
    }
});



// Route for login
app.post('/api/login', async(req, res) => {
    const { roll_no, password } = req.body;

    try {
        console.log('API login requested');

        // Query the database to check if the provided roll number exists in the login table
        const [existingUser] = await pool.execute('SELECT * FROM login WHERE roll_no = ?', [roll_no]);

        if (existingUser.length === 0) {
            // If the roll number doesn't exist in the login table, return an error
            console.log("No user found");
            return res.status(400).json({ error: 'Invalid roll number' });
        }

        // Verify the password
        const isPasswordValid = await bcrypt.compare(password, existingUser[0].password);

        if (!isPasswordValid) {
            // If the password is incorrect, return an error
            console.log("Invalid password");
            return res.status(400).json({ error: 'Invalid password' });
        }

        // Check if the user is active
        const isActive = existingUser[0].is_active;

        if (isActive === 0) {
            // If the user is not active, return a message
            console.log("User is no longer active");
            return res.status(400).json({ error: 'You are no longer an active user' });
        }

        // Check if the roll number exists in the profile table
        const [existingProfile] = await pool.execute('SELECT * FROM profile WHERE roll_no = ?', [roll_no]);
        let profileExists = 0;

        if (existingProfile.length > 0) {
            // If the roll number exists in the profile table, set profileExists to 1
            profileExists = 1;
        }

        // Call function to create token
        const token = createtoken(req, res, existingUser);
        console.log("Token:", token);

        // Send response
        res.json({ isValid: true, profile: profileExists, token });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// Route for user registration
app.post('/api/register', async(req, res) => {
    const { roll_no, date, role_id, sport_id, year } = req.body;

    try {
        console.log('API registration requested');

        // Check if the roll number already exists (case-insensitive check)
        const [existingUser] = await pool.execute('SELECT * FROM login WHERE LOWER(roll_no) = LOWER(?)', [roll_no]);

        // Check if any rows were returned
        if (existingUser.length > 0) {
            console.log('User with the same roll number already exists');
            return res.status(400).json({ error: 'User with the same roll number already exists' });
        }

        // Set password to roll_no
        const password = roll_no;

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new user into the login table
        const loginResult = await pool.execute('INSERT INTO login (roll_no, password, is_active, date, role_id) VALUES (?, ?, ?, ?, ?)', [roll_no, hashedPassword, 1, date, role_id]);

        // Insert sport_id and year into the profile table
        const profileResult = await pool.execute('INSERT INTO profile (roll_no, sport_id, year) VALUES (?, ?, ?)', [roll_no, sport_id, year]);

        // Send response
        res.json({ success: true, message: 'User registered successfully' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});




// Route for adding sports
app.post('/api/addsports', async(req, res) => {
    const { sport_name } = req.body;

    try {
        console.log('API addsports requested');

        // Check if the sport already exists (case-insensitive)
        const [existingSport] = await pool.execute('SELECT * FROM sports WHERE LOWER(sport_name) = LOWER(?)', [sport_name]);

        if (existingSport.length > 0) {
            return res.status(400).json({ error: 'Sport already exists' });
        }

        // Get the maximum sport_id from the database
        const [maxSportId] = await pool.execute('SELECT MAX(sport_id) AS maxSportId FROM sports');

        // Calculate the next sport_id
        const nextSportId = maxSportId[0].maxSportId + 1;

        // Insert new sport into the sports table with the calculated sport_id
        const result = await pool.execute('INSERT INTO sports (sport_id, sport_name) VALUES (?, ?)', [nextSportId, sport_name]);

        // Send response
        res.json({ success: true, message: 'Sport added successfully' });
    } catch (error) {
        console.error('Error adding sport:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
})

// API endpoint for displaying sports data
app.get('/api/displaysports', async(req, res) => {
    try {
        console.log('API displaysports requested');

        // Retrieve data from the sports table
        const [sportsData] = await pool.execute('SELECT * FROM sports');

        // Send response with the retrieved sports data
        res.json({ success: true, sports: sportsData });
    } catch (error) {
        console.error('Error displaying sports data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Route for adding security information
app.post('/api/addsecurity', async(req, res) => {
    let { roll_no, dob, hospital_born, school, fav_friend } = req.body;

    // Convert roll_no, hospital_born, school, and fav_friend to lowercase
    roll_no = roll_no.toLowerCase();
    hospital_born = hospital_born.toLowerCase();
    school = school.toLowerCase();
    fav_friend = fav_friend.toLowerCase();

    try {
        console.log('API addsecurity requested');

        // Check if the roll_no already exists in the database
        const [existingEntry] = await pool.execute('SELECT * FROM qa WHERE LOWER(roll_no) = ?', [roll_no]);

        if (existingEntry.length > 0) {
            return res.status(400).json({ error: 'Security information for this roll number already exists' });
        }

        // Insert new security information into the qa table
        const result = await pool.execute('INSERT INTO qa (roll_no, dob, hospital_born, school, fav_friend) VALUES (?, ?, ?, ?, ?)', [roll_no, dob, hospital_born, school, fav_friend]);

        // Send response
        res.json({ success: true, message: 'Security information added successfully' });
    } catch (error) {
        console.error('Error adding security information:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for adding a profile
app.post('/addprofile', upload.single('photo'), async(req, res) => {
    let { roll_no, name, email, sport_id, phone } = req.body;

    // Convert roll_no and phone to lowercase
    roll_no = roll_no.toLowerCase();


    try {
        console.log('API add profile requested');

        if (!req.file) {
            throw new Error('No photo uploaded.');
        }

        // Inserting data into the profile table
        const insertQuery = `INSERT INTO profile (roll_no, name, photo_path, email, sport_id, phone) VALUES (?, ?, ?, ?, ?, ?)`;
        connection.query(insertQuery, [roll_no, name, req.file.path, email, sport_id, phone], (error, results, fields) => {
            if (error) {
                console.error("Error inserting data: ", error);
                res.status(500).json({ error: "Error inserting data into the database" });
            } else {
                console.log("Data inserted successfully");
                res.status(200).json({ success: true, message: "Profile added successfully" });
            }
        });
    } catch (error) {
        console.error("Error adding profile: ", error);
        res.status(500).json({ error: "Error adding profile." });
    }
});

// API endpoint for verifying roll number and date of birth
app.post('/api/verifyroleno', async(req, res) => {
    let { roll_no, dob } = req.body;

    roll_no = roll_no.toLowerCase(); // Convert roll_no to lowercase

    try {
        console.log('API verifyroleno requested');

        // Check if the user exists in the login table with the provided roll number and DOB
        const [user] = await pool.execute('SELECT * FROM login WHERE LOWER(roll_no) = ? AND dob = ?', [roll_no, dob]);

        if (user.length > 0) {
            // If user exists and credentials are correct, return success
            console.log('User authenticated');
            res.json({ success: true, message: 'User authenticated successfully' });
        } else {
            // If user doesn't exist or credentials are incorrect, return error
            console.log('Invalid credentials');
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error verifying credentials:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for verifying security question answer
app.post('/api/verifysecurity', async(req, res) => {
    const { roll_no, qa_id, qa_answer } = req.body;

    // Convert roll_no to lowercase
    const lowercaseRollNo = roll_no.toLowerCase();

    try {
        console.log('API verifysecurity requested');

        let columnToCheck;

        // Determine the column to check based on qa_id
        switch (qa_id) {
            case 1:
                columnToCheck = 'hospital_born';
                break;
            case 2:
                columnToCheck = 'school';
                break;
            case 3:
                columnToCheck = 'fav_friend';
                break;
            default:
                return res.status(400).json({ error: 'Invalid security question ID' });
        }

        // Fetch the correct answer from the qa table based on roll_no
        const [securityInfo] = await pool.execute(`SELECT ${columnToCheck} FROM qa WHERE LOWER(roll_no) = ?`, [lowercaseRollNo]);

        // Check if the security information exists for the provided roll_no
        if (securityInfo.length === 0) {
            return res.status(404).json({ error: 'Security information not found' });
        }

        // Extract the correct answer from the fetched security information
        const correctAnswer = securityInfo[0][columnToCheck];

        // Compare the provided answer with the correct answer
        if (correctAnswer.toLowerCase() === qa_answer.toLowerCase()) {
            // If the answers match, send success response
            return res.json({ success: true, message: 'Security question answer is correct' });
        } else {
            // If the answers don't match, send error response
            return res.status(400).json({ error: 'Security question answer is incorrect' });
        }
    } catch (error) {
        console.error('Error verifying security question answer:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for resetting password
app.post('/api/resetpassword', async(req, res) => {
    let { roll_no, new_password } = req.body;

    // Convert roll_no to lowercase
    roll_no = roll_no.toLowerCase();

    try {
        // Log API request
        console.log('API resetpassword requested');

        // Check if the roll number exists in the login table
        const [existingUser] = await pool.execute('SELECT * FROM login WHERE LOWER(roll_no) = ?', [roll_no]);

        // If roll number doesn't exist, return error
        if (existingUser.length === 0) {
            return res.status(400).json({ error: 'Invalid roll number' });
        }

        // Update password for the user with provided roll number
        const updateQuery = 'UPDATE login SET password = ? WHERE LOWER(roll_no) = ?';
        await pool.execute(updateQuery, [new_password, roll_no]);

        // Send response
        res.json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
        // Handle errors
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for hard resetting password
app.post('/api/hardresetpassword', async(req, res) => {
    const { roll_no } = req.body;

    try {
        console.log('API hardresetpassword requested');

        // Set password to roll_no
        const password = roll_no;

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update the password for the user with the provided roll number
        const updateQuery = 'UPDATE login SET password = ? WHERE roll_no = ?';
        const [updateResult] = await pool.execute(updateQuery, [hashedPassword, roll_no]);

        // Check if any rows were affected by the update
        if (updateResult.affectedRows === 0) {
            console.log('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        // Send response
        res.json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// API endpoint for deactivating a user
app.post('/api/deactivateuser', async(req, res) => {
    let { roll_no } = req.body;

    // Convert roll_no to lowercase
    roll_no = roll_no.toLowerCase();

    try {
        console.log('API deactivateuser requested');

        // Update is_active to 0 for the user with the provided roll number
        const updateQuery = 'UPDATE login SET is_active = 0 WHERE LOWER(roll_no) = ?';
        const [updateResult] = await pool.execute(updateQuery, [roll_no]);

        // Check if any rows were affected by the update
        if (updateResult.affectedRows === 0) {
            console.log('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        // Send response
        res.json({ success: true, message: 'User deactivated successfully' });
    } catch (error) {
        console.error('Error deactivating user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// API endpoint for changing a user's sport
app.post('/api/changesport', async(req, res) => {
    let { roll_no, sport_id } = req.body;

    // Convert roll_no to lowercase
    roll_no = roll_no.toLowerCase();

    try {
        console.log('API changesport requested');

        // Update sport_id for the user with the provided roll number
        const updateQuery = 'UPDATE profile SET sport_id = ? WHERE LOWER(roll_no) = ?';
        const [updateResult] = await pool.execute(updateQuery, [sport_id, roll_no]);

        // Check if any rows were affected by the update
        if (updateResult.affectedRows === 0) {
            console.log('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        // Send response
        res.json({ success: true, message: 'User sport updated successfully' });
    } catch (error) {
        console.error('Error updating user sport:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for displaying roles data
app.get('/api/displayroles', async(req, res) => {
    try {
        console.log('API displayroles requested');

        // Retrieve data from the roles table
        const [rolesData] = await pool.execute('SELECT * FROM roles');

        // Send response with the retrieved roles data
        res.json({ success: true, roles: rolesData });
    } catch (error) {
        console.error('Error displaying roles data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// API endpoint for changing a user's role
app.post('/api/changeroll', async(req, res) => {
    let { roll_no, role_id } = req.body;

    // Convert roll_no to lowercase
    roll_no = roll_no.toLowerCase();

    try {
        console.log('API changeroll requested');

        // Update role_id for the user with the provided roll number
        const updateQuery = 'UPDATE login SET role_id = ? WHERE LOWER(roll_no) = ?';
        const [updateResult] = await pool.execute(updateQuery, [role_id, roll_no]);

        // Check if any rows were affected by the update
        if (updateResult.affectedRows === 0) {
            console.log('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        // Send response
        res.json({ success: true, message: 'User role updated successfully' });
    } catch (error) {
        console.error('Error updating user role:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for displaying filtered members
app.post('/api/displaymembersfilter', async(req, res) => {
    const { year, sport_id } = req.body;

    try {
        console.log('API displaymembersfilter requested');

        let selectQuery = 'SELECT * FROM profile';

        // Select roll_no from login table where role_id != 0
        const [rollNos] = await pool.execute('SELECT roll_no FROM login WHERE role_id != 0');

        // Check if roll numbers are retrieved
        if (rollNos.length > 0) {
            // Extract roll numbers from the result
            const rollNumbers = rollNos.map(row => row.roll_no);

            // Build the WHERE clause based on retrieved roll numbers
            selectQuery += ` WHERE roll_no IN (${rollNumbers.map(() => '?').join(', ')})`;

            // Add filter for sport_id if provided
            if (sport_id) {
                selectQuery += ' AND sport_id = ?';
            }

            // Add filter for year if provided
            if (year) {
                selectQuery += ' AND year = ?';
            }

            // Prepare filter parameters
            let filterParams = rollNumbers;
            if (sport_id && year) {
                filterParams.push(sport_id, year);
            } else if (sport_id) {
                filterParams.push(sport_id);
            } else if (year) {
                filterParams.push(year);
            }

            // Execute the query with appropriate parameters
            const [filteredMembers] = await pool.execute(selectQuery, filterParams);

            // Send response with the filtered members
            res.json({ success: true, filteredMembers });
        } else {
            // If no roll numbers are retrieved, send an empty response
            res.json({ success: true, filteredMembers: [] });
        }
    } catch (error) {
        console.error('Error displaying filtered members:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// API endpoint for updating profile year and concatenating new year with existing one
app.post('/api/nextyear', async(req, res) => {
    let { roll_no, year } = req.body;

    // Convert roll_no to lowercase
    roll_no = roll_no.toLowerCase();

    try {
        console.log('API nextyear requested');

        // Retrieve existing year for the user with the provided roll number
        const [existingYear] = await pool.execute('SELECT year FROM profile WHERE LOWER(roll_no) = ?', [roll_no]);

        let newYear;
        if (existingYear.length > 0) {
            // Concatenate new year with existing one if it exists
            newYear = existingYear[0].year ? `${existingYear[0].year},${year}` : year;

            // Update profile year for the user with the provided roll number
            const updateQuery = 'UPDATE profile SET year = ? WHERE LOWER(roll_no) = ?';
            await pool.execute(updateQuery, [newYear, roll_no]);
        } else {
            // If the user doesn't exist, return an error
            console.log('User not found');
            return res.status(404).json({ error: 'User not found' });
        }

        // Send response
        res.json({ success: true, message: 'Year updated successfully' });
    } catch (error) {
        console.error('Error updating year:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});





// API endpoint for adding an event
app.post('/api/addevent', async(req, res) => {
    let { event_name, sport_id, date, time, entry_fee, is_team, event_description, no_of_prize, category, gender, form_link, last_date, place, roll_no, created_date } = req.body;

    // Convert event_name, event_description, place, and roll_no (created_by) to lowercase
    event_name = event_name.toLowerCase();
    event_description = event_description.toLowerCase();
    place = place.toLowerCase();
    roll_no = roll_no.toLowerCase();

    try {
        console.log('API addevent requested');

        // Insert new event into the event table with provided created_date
        const insertQuery = `INSERT INTO event (event_name, sport_id, date, time, entry_fee, is_team, event_description, no_of_prize, category, gender, form_link, last_date, place, created_by, created_date, approval_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        const result = await pool.execute(insertQuery, [event_name, sport_id, date, time, entry_fee, is_team, event_description, no_of_prize, category, gender, form_link, last_date, place, roll_no, created_date, 0]);

        // Send response
        res.json({ success: true, message: 'Event added successfully' });
    } catch (error) {
        console.error('Error adding event:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// API endpoint for event approval
app.post('/api/eventapproval', async(req, res) => {
    const { event_id, approval_date } = req.body;

    try {
        console.log('API eventapproval requested');

        // Set approval_status to 1 and update approval_date
        const updateQuery = `UPDATE event SET approval_status = ?, approval_date = ? WHERE event_id = ?`;
        const result = await pool.execute(updateQuery, [1, approval_date, event_id]);

        // Check if any rows were affected by the update
        if (result[0].affectedRows === 0) {
            console.log('Event not found');
            return res.status(404).json({ error: 'Event not found' });
        }

        // Send response
        res.json({ success: true, message: 'Event approval status updated successfully' });
    } catch (error) {
        console.error('Error updating event approval status:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for adding an event by admin
app.post('/api/adminaddevent', async(req, res) => {
    // Convert certain fields to lowercase before destructuring
    const { event_name, event_description, place, created_by, created_date, sport_id, date, time, entry_fee, is_team, no_of_prize, category, gender, form_link, last_date } = req.body;

    try {
        console.log('API adminaddevent requested');

        // Insert new event into the event table with approval_status = 1
        const insertQuery = `INSERT INTO event (event_name, sport_id, date, time, place, entry_fee, is_team, event_description, no_of_prize, category, gender, form_link, last_date, created_by, created_date, approval_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        const result = await pool.execute(insertQuery, [event_name.toLowerCase(), sport_id, date, time, place.toLowerCase(), entry_fee, is_team, event_description.toLowerCase(), no_of_prize, category, gender, form_link, last_date, created_by.toLowerCase(), created_date, 1]);

        // Send response
        res.json({ success: true, message: 'Event added successfully' });
    } catch (error) {
        console.error('Error adding event:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// API endpoint for displaying approved event
app.get('/api/displayevent', async(req, res) => {
    try {
        console.log('API displayevent requested');

        // Select event with approval_status = 1
        const selectQuery = 'SELECT * FROM event WHERE approval_status = ?';
        const [event] = await pool.execute(selectQuery, [1]);

        // Send response with the retrieved event
        res.json({ success: true, event });
    } catch (error) {
        console.error('Error displaying event:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});




// API endpoint for retrieving event created by a user
app.post('/api/createdevent', async(req, res) => {
    const { roll_no } = req.body; // Get roll number from request body and convert to lowercase
    const rollNoLower = roll_no.toLowerCase();

    try {
        console.log('API createdevent requested');

        // Retrieve event created by the specified user from the profile table
        const selectQuery = 'SELECT * FROM profile WHERE created_by = ?';
        const [createdevent] = await pool.execute(selectQuery, [rollNoLower]);

        // Send response with the created event
        res.json({ success: true, createdevent });
    } catch (error) {
        console.error('Error retrieving created event:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



// API endpoint for updating an event
app.post('/api/updateevent', async(req, res) => {
    const { event_id, event_name, sport_id, date, time, entry_fee, is_team, event_description, no_of_prize, category, gender, form_link, last_date, place } = req.body;

    try {
        console.log('API updateevent requested');

        const [eventRows] = await pool.execute('SELECT approval_status FROM event WHERE event_id = ?', [event_id]);

        if (eventRows.length === 0) {
            return res.status(404).json({ error: 'Event not found' });
        }

        const approvalStatus = eventRows[0].approval_status;
        if (approvalStatus === 1) {
            return res.status(403).json({ error: 'Event is already published and cannot be edited' });
        }

        // Update the event in the database
        const updateQuery = `
            UPDATE event 
            SET 
                event_name = ?, 
                sport_id = ?, 
                date = ?, 
                time = ?, 
                entry_fee = ?, 
                is_team = ?, 
                event_description = ?, 
                no_of_prize = ?, 
                category = ?, 
                gender = ?, 
                form_link = ?, 
                last_date = ?, 
                place = ? 
            WHERE 
                event_id = ?`;

        await pool.execute(updateQuery, [
            event_name,
            sport_id,
            date,
            time,
            entry_fee,
            is_team,
            event_description,
            no_of_prize,
            category,
            gender,
            form_link,
            last_date,
            place,
            event_id
        ]);

        // Send success response
        res.json({ success: true, message: 'Event updated successfully' });
    } catch (error) {
        console.error('Error updating event:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// API endpoint for updating an event by admin
app.post('/api/adminupdateevent', async(req, res) => {
    const { event_id, event_name, sport_id, date, time, entry_fee, is_team, event_description, no_of_prize, category, gender, form_link, last_date, place } = req.body;

    try {
        console.log('API adminupdateevent requested');

        // Update the event in the database
        const updateQuery = `
            UPDATE event 
            SET 
                event_name = ?, 
                sport_id = ?, 
                date = ?, 
                time = ?, 
                entry_fee = ?, 
                is_team = ?, 
                event_description = ?, 
                no_of_prize = ?, 
                category = ?, 
                gender = ?, 
                form_link = ?, 
                last_date = ?, 
                place = ? 
            WHERE 
                event_id = ?`;

        await pool.execute(updateQuery, [
            event_name,
            sport_id,
            date,
            time,
            entry_fee,
            is_team,
            event_description,
            no_of_prize,
            category,
            gender,
            form_link,
            last_date,
            place,
            event_id
        ]);

        // Send success response
        res.json({ success: true, message: 'Event updated successfully' });
    } catch (error) {
        console.error('Error updating event by admin:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});








// API endpoint for uploading an image
app.post('/upload', upload.single('image'), async(req, res) => {
    try {
        if (!req.file) {
            throw new Error('No file uploaded.');
        }

        // Inserting data into the table
        const insertQuery = `INSERT INTO test_img (img_path) VALUES (?)`;
        connection.query(insertQuery, [req.file.path], (error, results, fields) => {
            if (error) {
                console.error("Error inserting data: ", error);
                res.status(500).send("Error inserting data into the database");
            } else {
                console.log("Data inserted successfully");
                res.status(200).send("Image uploaded and data inserted successfully");
            }
        });
    } catch (error) {
        console.error("Error uploading image: ", error);
        res.status(500).send("Error uploading image.");
    }
});


// API endpoint for fetching all image paths
app.get('/images', (req, res) => {
    // Query to select all image paths from the database
    const selectQuery = `SELECT img_path FROM test_img`;

    // Execute the query
    connection.query(selectQuery, (error, results, fields) => {
        if (error) {
            console.error("Error fetching images: ", error);
            res.status(500).send("Error fetching images from the database");
        } else {
            // Extract image paths from the results
            const imagePaths = results.map(result => result.img_path);
            // Send the image paths as a response
            res.status(200).json(imagePaths);
        }
    });
});



app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
}).on('error', (err) => {
    console.error('Server start error:', err);
});