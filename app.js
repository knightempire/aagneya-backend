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
    port: 19516,
    // port: 3306,
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
    // Assuming rows contain user data with a roll_no field
    const roll_no = rows[0].roll_no;

    // Sign the token with the roll_no instead of email
    const token = jwt.sign({ roll_no: roll_no }, JWT_SECRET, {
        expiresIn: JWT_EXPIRY,
    });

    // Assuming you are using Express and want to store the token in the session
    req.session.jwtToken = token;

    // Return the token
    return token;
};






//function to verify token
// Middleware to authenticate token and retrieve user data
// async function getUserDataByroll_no(roll_no) {
//     try {
//         // Query the database to find the user by roll_no
//         const user = await User.findOne({ roll_no });

//         // If user is found, return user data
//         if (user) {
//             return {
//                 id: user.id,
//                 roll_no: user.roll_no,
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

const authenticateToken = (req, res, next) => {
    try {
        // Check if Authorization header exists
        if (!req.headers.authorization) {
            return res.redirect('#'); // Redirect to login page
        }

        // Retrieve token from request headers and split it
        const token = req.headers.authorization.split(' ')[1];
        // console.log("Token:", token); // Print token value

        // Verify token
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) {
                console.error('Authentication error:', err.message);
                // Token is invalid or expired, send 401 Unauthorized response to client
                return res.status(401).json({ error: 'Unauthorized' });
            } else {
                req.user = decoded; // Set decoded information in request object
                // console.log('Decoded user:', decoded);
                next(); // Proceed to next middleware
            }
        });
    } catch (err) {
        console.error('Error in authentication middleware:', err.message);
        res.status(500).send('Internal Server Error');
    }
};




app.post('/api/decodeToken', [authenticateToken, async(req, res) => {
    console.log('api decode requested');
    try {
        // Extract the token from the request body
        const { token } = req.body;

        // Verify and decode the token
        const decodedToken = jwt.verify(token, JWT_SECRET);

        // Extract roll_no from decoded token
        const { roll_no } = decodedToken;

        // Check if roll_no is defined
        if (!roll_no) {
            return res.status(400).json({ error: 'roll_no not found in token' });
        }

        // Get a connection from the pool
        const connection = await pool.getConnection();

        try {
            // Query the database to retrieve user data based on roll_no
            const [rows] = await connection.execute('SELECT l.roll_no, l.is_active, l.role_id, l.spl_role, p.name FROM login l LEFT JOIN profile p ON l.roll_no = p.roll_no WHERE l.roll_no = ?', [roll_no]);

            // Check if user exists in the database
            if (rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Get the user data from the query results
            const userData = rows[0];

            // Determine if profile exists
            userData.profile = rows[0].name && rows[0].name !== 'Unknown' ? 1 : 0;
            console.log(userData.profile)

            // Set name to 'User' if it's null or undefined
            userData.name = rows[0].name || 'User';

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
}]);


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

        // Assuming you want to retrieve role_id from existingUser
        const { role_id } = existingUser[0];

        // Check if the roll number exists in the profile table
        const [existingProfile] = await pool.execute('SELECT * FROM profile WHERE roll_no = ?', [roll_no]);
        let profileExists = 0;

        console.log(existingProfile)
        if (existingProfile.length > 0) {
            // If the roll number exists in the profile table, set profileExists to 1
            const profileData = existingProfile[0];
            if (profileData.name && profileData.name !== "Unknown") {
                profileExists = 1;
            }
        }

        // Call function to create token
        const token = createtoken(req, res, existingUser);
        console.log("Token:", token);

        // Send response
        res.json({ isValid: true, profile: profileExists, token, role_id });
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
        // Set password to roll_nNo
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
app.post('/api/addsports', [authenticateToken, async(req, res) => {
    const { sport_name } = req.body;

    try {
        console.log('API addsports requested');

        // Convert sport_name to lowercase
        const lowercaseSportName = sport_name.toLowerCase();

        // Check if the sport already exists (case-insensitive)
        const [existingSport] = await pool.execute('SELECT * FROM sports WHERE LOWER(sport_name) = ?', [lowercaseSportName]);

        if (existingSport.length > 0) {
            return res.status(400).json({ error: 'Sport already exists' });
        }

        // Get the maximum sport_id from the database
        const [maxSportId] = await pool.execute('SELECT MAX(sport_id) AS maxSportId FROM sports');

        // Calculate the next sport_id
        const nextSportId = maxSportId[0].maxSportId + 1 || 1; // Handle the case where there are no existing sports

        // Insert new sport into the sports table with the calculated sport_id and lowercase sport_name
        const result = await pool.execute('INSERT INTO sports (sport_id, sport_name) VALUES (?, ?)', [nextSportId, lowercaseSportName]);

        // Send response
        res.json({ success: true, message: 'Sport added successfully' });
    } catch (error) {
        console.error('Error adding sport:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// API endpoint for displaying sports data
app.get('/api/displaysports', [authenticateToken, async(req, res) => {
    try {
        console.log('API displaysports requested');

        // Retrieve data from the sports table
        const [sportsData] = await pool.execute('SELECT * FROM sports ORDER BY sport_name');

        // Send response with the retrieved sports data
        res.json({ success: true, sports: sportsData });
    } catch (error) {
        console.error('Error displaying sports data:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


// Route for adding security information
app.post('/api/addsecurity', [authenticateToken, async(req, res) => {
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
}]);


// API endpoint for adding a profile
app.post('/api/addprofile', [authenticateToken, upload.single('photo'), async(req, res) => {
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
}]);

// API endpoint for verifying roll number and date of birth
app.post('/api/verifyroleno', [authenticateToken, async(req, res) => {
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
}]);


// API endpoint for verifying security question answer
app.post('/api/verifysecurity', [authenticateToken, async(req, res) => {
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
}]);


// API endpoint for resetting password
app.post('/api/resetpassword', [authenticateToken, async(req, res) => {
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
}]);


// API endpoint for hard resetting password
app.post('/api/hardresetpassword', [authenticateToken, async(req, res) => {
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
}]);



// API endpoint for deactivating a user
app.post('/api/deactivateuser', [authenticateToken, async(req, res) => {
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
}]);



// API endpoint for changing a user's sport
app.post('/api/changesport', [authenticateToken, async(req, res) => {
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
}]);


// API endpoint for displaying roles data
app.get('/api/displayroles', [authenticateToken, async(req, res) => {
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
}]);



// API endpoint for changing a user's role
app.post('/api/changeroll', [authenticateToken, async(req, res) => {
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
}]);


// API endpoint for displaying filtered members
app.post('/api/displaymembersfilter', [authenticateToken, async(req, res) => {
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
}]);



// API endpoint for updating profile year and concatenating new year with existing one
app.post('/api/nextyear', [authenticateToken, async(req, res) => {
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
}]);





// API endpoint for adding an event
app.post('/api/addevent', [authenticateToken, async(req, res) => {
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
}]);



// API endpoint for event approval
app.post('/api/eventapproval', [authenticateToken, async(req, res) => {
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
}]);


// API endpoint for adding an event by admin
app.post('/api/adminaddevent', [authenticateToken, async(req, res) => {
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
}]);



// API endpoint for displaying approved event
app.get('/api/displayevent', [authenticateToken, async(req, res) => {
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
}]);




// API endpoint for retrieving event created by a user
app.post('/api/createdevent', [authenticateToken, async(req, res) => {
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
}]);



// API endpoint for updating an event
app.post('/api/updateevent', [authenticateToken, async(req, res) => {
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
}]);


// API endpoint for updating an event by admin
app.post('/api/adminupdateevent', [authenticateToken, async(req, res) => {
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
}]);



// Add Blog
app.post('/api/addblog', [authenticateToken, async(req, res) => {
    let { title, img_path, description, creation_date, approval_date, created_by } = req.body;

    // Convert necessary fields to lowercase
    title = title.toLowerCase();
    description = description.toLowerCase();
    created_by = created_by.toLowerCase();

    try {
        console.log('API addblog requested');

        // Insert new blog into the blog table with provided creation_date and approval_date
        const insertQuery = `INSERT INTO blog (title, img_path, description, creation_date, approval_date, created_by, is_approved) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        await pool.execute(insertQuery, [title, img_path, description, creation_date, approval_date, created_by, 0]);

        res.json({ success: true, message: 'Blog added successfully' });
    } catch (error) {
        console.error('Error adding blog:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Blog Approval
app.post('/api/blogapproval', [authenticateToken, async(req, res) => {
    const { blog_id, approval_date } = req.body;

    try {
        console.log('API blogapproval requested');

        // Set is_approved to 1 and update approval_date
        const updateQuery = `UPDATE blog SET is_approved = ?, approval_date = ? WHERE blog_id = ?`;
        const result = await pool.execute(updateQuery, [1, approval_date, blog_id]);

        if (result[0].affectedRows === 0) {
            console.log('Blog not found');
            return res.status(404).json({ error: 'Blog not found' });
        }

        res.json({ success: true, message: 'Blog approval status updated successfully' });
    } catch (error) {
        console.error('Error updating blog approval status:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Admin Add Blog
app.post('/api/adminaddblog', [authenticateToken, async(req, res) => {
    const { title, img_path, description, created_by, creation_date, approval_date } = req.body;

    try {
        console.log('API adminaddblog requested');

        // Insert new blog into the blog table with is_approved = 1
        const insertQuery = `INSERT INTO blog (title, img_path, description, creation_date, approval_date, created_by, is_approved) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        await pool.execute(insertQuery, [title.toLowerCase(), img_path, description.toLowerCase(), creation_date, approval_date, created_by.toLowerCase(), 1]);

        res.json({ success: true, message: 'Blog added successfully' });
    } catch (error) {
        console.error('Error adding blog:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Display Approved Blogs
app.get('/api/displayblogs', [authenticateToken, async(req, res) => {
    try {
        console.log('API displayblogs requested');

        const selectQuery = 'SELECT * FROM blog WHERE is_approved = ?';
        const [blogs] = await pool.execute(selectQuery, [1]);

        res.json({ success: true, blogs });
    } catch (error) {
        console.error('Error displaying blogs:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Retrieve Created Blogs by Roll Number
app.post('/api/createdblogs', [authenticateToken, async(req, res) => {
    const { roll_no } = req.body;
    const rollNoLower = roll_no.toLowerCase();

    try {
        console.log('API createdblogs requested');

        // Retrieve blogs created by the specified roll number
        const selectQuery = 'SELECT * FROM blog WHERE created_by = ?';
        const [createdBlogs] = await pool.execute(selectQuery, [rollNoLower]);

        res.json({ success: true, createdBlogs });
    } catch (error) {
        console.error('Error retrieving created blogs:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


app.post('/api/updateblog', [authenticateToken, async(req, res) => {
    const { blog_id, title, img_path, description, creation_date, approval_date } = req.body;

    try {
        console.log('API updateblog requested');

        // Check if the blog exists and its current is_approved status
        const [blogRows] = await pool.execute('SELECT is_approved FROM blog WHERE blog_id = ?', [blog_id]);

        if (blogRows.length === 0) {
            return res.status(404).json({ error: 'Blog not found' });
        }

        const isApproved = blogRows[0].is_approved;

        // Check if the blog is already approved
        if (isApproved === 1) {
            return res.status(403).json({ error: 'Blog is already published and cannot be edited' });
        }

        // Update the blog
        const updateQuery = `
            UPDATE blog 
            SET 
                title = ?, 
                img_path = ?, 
                description = ?, 
                creation_date = ?, 
                approval_date = ? 
            WHERE 
                blog_id = ?`;

        await pool.execute(updateQuery, [
            title,
            img_path,
            description,
            creation_date,
            approval_date,
            blog_id
        ]);

        res.json({ success: true, message: 'Blog updated successfully' });
    } catch (error) {
        console.error('Error updating blog:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


// Admin Update Blog
app.post('/api/adminupdateblog', [authenticateToken, async(req, res) => {
    const { blog_id, title, img_path, description, creation_date, approval_date } = req.body;

    try {
        console.log('API adminupdateblog requested');

        const updateQuery = `
            UPDATE blog 
            SET 
                title = ?, 
                img_path = ?, 
                description = ?, 
                creation_date = ?, 
                approval_date = ? 
            WHERE 
                blog_id = ?`;

        await pool.execute(updateQuery, [
            title,
            img_path,
            description,
            creation_date,
            approval_date,
            blog_id
        ]);

        res.json({ success: true, message: 'Blog updated successfully' });
    } catch (error) {
        console.error('Error updating blog by admin:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



// Add Achievement
app.post('/api/addachievement', [authenticateToken, async(req, res) => {
    let { description, achievement_date, roll_no, name, photo_path, is_team, is_inside_campus } = req.body;

    // Convert necessary fields to lowercase
    roll_no = roll_no.toLowerCase();
    name = name.toLowerCase();
    description = description.toLowerCase();

    try {
        console.log('API addachievement requested');

        // Insert new achievement into the achievement table
        const insertQuery = `INSERT INTO achievement (description, achievement_date, roll_no, name, photo_path, is_team, is_inside_campus, is_display) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
        await pool.execute(insertQuery, [description, achievement_date, roll_no, name, photo_path, is_team, is_inside_campus, 0]);

        res.json({ success: true, message: 'Achievement added successfully' });
    } catch (error) {
        console.error('Error adding achievement:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Achievement Approval
app.post('/api/achievementapproval', [authenticateToken, async(req, res) => {
    const { achievement_id } = req.body;

    try {
        console.log('API achievementapproval requested');

        // Set is_display to 1
        const updateQuery = `UPDATE achievement SET is_display = ? WHERE achievement_id = ?`;
        const result = await pool.execute(updateQuery, [1, achievement_id]);

        if (result[0].affectedRows === 0) {
            console.log('Achievement not found');
            return res.status(404).json({ error: 'Achievement not found' });
        }

        res.json({ success: true, message: 'Achievement approval status updated successfully' });
    } catch (error) {
        console.error('Error updating achievement approval status:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Admin Add Achievement
app.post('/api/adminaddachievement', [authenticateToken, async(req, res) => {
    let { description, achievement_date, roll_no, name, photo_path, is_team, is_inside_campus } = req.body;

    // Convert necessary fields to lowercase
    roll_no = roll_no.toLowerCase();
    name = name.toLowerCase();
    description = description.toLowerCase();

    try {
        console.log('API adminaddachievement requested');

        // Insert new achievement into the achievement table with is_display = 1
        const insertQuery = `INSERT INTO achievement (description, achievement_date, roll_no, name, photo_path, is_team, is_inside_campus, is_display) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
        await pool.execute(insertQuery, [description, achievement_date, roll_no, name, photo_path, is_team, is_inside_campus, 1]);

        res.json({ success: true, message: 'Achievement added successfully' });
    } catch (error) {
        console.error('Error adding achievement:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Display Approved Achievements
app.get('/api/displayachievements', [authenticateToken, async(req, res) => {
    try {
        console.log('API displayachievements requested');

        const selectQuery = 'SELECT * FROM achievement WHERE is_display = ?';
        const [achievements] = await pool.execute(selectQuery, [1]);

        res.json({ success: true, achievements });
    } catch (error) {
        console.error('Error displaying achievements:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Retrieve Created Achievements by Roll Number
app.post('/api/createdachievements', [authenticateToken, async(req, res) => {
    const { roll_no } = req.body;
    const rollNoLower = roll_no.toLowerCase();

    try {
        console.log('API createdachievements requested');

        // Retrieve achievements created by the specified roll number
        const selectQuery = 'SELECT * FROM achievement WHERE roll_no = ?';
        const [createdAchievements] = await pool.execute(selectQuery, [rollNoLower]);

        res.json({ success: true, createdAchievements });
    } catch (error) {
        console.error('Error retrieving created achievements:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Update Achievement
app.post('/api/updateachievement', [authenticateToken, async(req, res) => {
    const { achievement_id, description, achievement_date, roll_no, name, photo_path, is_team, is_inside_campus } = req.body;

    try {
        console.log('API updateachievement requested');

        // Check if the achievement exists and its current is_display status
        const [achievementRows] = await pool.execute('SELECT is_display FROM achievement WHERE achievement_id = ?', [achievement_id]);

        if (achievementRows.length === 0) {
            return res.status(404).json({ error: 'Achievement not found' });
        }

        const isDisplay = achievementRows[0].is_display;

        // Check if the achievement is already displayed
        if (isDisplay === 1) {
            return res.status(403).json({ error: 'Achievement is already published and cannot be edited' });
        }

        // Update the achievement
        const updateQuery = `
            UPDATE achievement 
            SET 
                description = ?, 
                achievement_date = ?, 
                roll_no = ?, 
                name = ?, 
                photo_path = ?, 
                is_team = ?, 
                is_inside_campus = ? 
            WHERE 
                achievement_id = ?`;

        await pool.execute(updateQuery, [
            description,
            achievement_date,
            roll_no.toLowerCase(),
            name.toLowerCase(),
            photo_path,
            is_team,
            is_inside_campus,
            achievement_id
        ]);

        res.json({ success: true, message: 'Achievement updated successfully' });
    } catch (error) {
        console.error('Error updating achievement:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);

// Admin Update Achievement
app.post('/api/adminupdateachievement', [authenticateToken, async(req, res) => {
    const { achievement_id, description, achievement_date, roll_no, name, photo_path, is_team, is_inside_campus } = req.body;

    try {
        console.log('API adminupdateachievement requested');

        // Update the achievement in the database
        const updateQuery = `
            UPDATE achievement 
            SET 
                description = ?, 
                achievement_date = ?, 
                roll_no = ?, 
                name = ?, 
                photo_path = ?, 
                is_team = ?, 
                is_inside_campus = ? 
            WHERE 
                achievement_id = ?`;

        await pool.execute(updateQuery, [
            description,
            achievement_date,
            roll_no.toLowerCase(),
            name.toLowerCase(),
            photo_path,
            is_team,
            is_inside_campus,
            achievement_id
        ]);

        res.json({ success: true, message: 'Achievement updated successfully' });
    } catch (error) {
        console.error('Error updating achievement:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



// Route for registering candidates for an election
app.post('/api/electionregister', [authenticateToken, async(req, res) => {
    const { election_id, roll_no, role_id } = req.body;

    try {
        console.log('API electionregister requested');
        // Fetch candidate with the same reg_roll_no for the given election_id
        const fetchCandidateQuery = 'SELECT candidate_id, role_id FROM candidate WHERE election_id = ? AND reg_roll_no = ?';
        const [candidateRows] = await pool.execute(fetchCandidateQuery, [election_id, roll_no]);

        // Check if candidate already exists
        if (candidateRows.length > 0) {
            const { role_id } = candidateRows[0];

            // Fetch role_name based on role_id
            const fetchRoleQuery = 'SELECT role_name FROM roles WHERE role_id = ?';
            const [roleRows] = await pool.execute(fetchRoleQuery, [role_id]);

            if (roleRows.length > 0) {
                const { role_name } = roleRows[0];
                return res.status(400).json({ error: `You are already registered for this election as ${role_name}` });
            }
        }

        // If candidate does not exist, proceed with insertion
        const insertQuery = 'INSERT INTO candidate (election_id, reg_roll_no, role_id) VALUES (?, ?, ?)';
        const result = await pool.execute(insertQuery, [election_id, roll_no, role_id]);

        res.json({ success: true, message: 'Registration successful' });
    } catch (error) {
        console.error('Error registering candidate:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



// Route for opening registration for an election
app.post('/api/electionregisteropen', [authenticateToken, async(req, res) => {
    const { election_id } = req.body;

    try {
        console.log('API electionregisteropen requested');
        // Check if the election is already open for registration
        const checkQuery = 'SELECT is_register FROM election WHERE election_id = ?';
        const [rows] = await pool.execute(checkQuery, [election_id]);

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Election not found' });
        }

        const { is_register } = rows[0];

        // If already open for registration, return error
        if (is_register === 1) {
            return res.status(400).json({ error: 'Registration is already open for this election' });
        }

        // Update election to set is_register = 1
        const updateQuery = 'UPDATE election SET is_register = 1 WHERE election_id = ?';
        await pool.execute(updateQuery, [election_id]);

        res.json({ success: true, message: 'Registration opened successfully' });
    } catch (error) {
        console.error('Error opening registration for election:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



// Route for closing registration for an election
app.post('/api/electionregisterclose', [authenticateToken, async(req, res) => {
    const { election_id } = req.body;

    try {
        console.log('API electionregisterclose requested');
        // Fetch current is_register status for the election
        const fetchQuery = 'SELECT is_register FROM election WHERE election_id = ?';
        const [rows] = await pool.execute(fetchQuery, [election_id]);

        // Check if election exists
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Election not found' });
        }

        const { is_register } = rows[0];

        // If registration is already closed, return error
        if (is_register === 0) {
            return res.status(400).json({ error: 'Registration for this election is already closed' });
        }

        // Update election to set is_register = 0
        const updateQuery = 'UPDATE election SET is_register = 0 WHERE election_id = ?';
        const [result] = await pool.execute(updateQuery, [election_id]);

        res.json({ success: true, message: 'Registration closed successfully' });
    } catch (error) {
        console.error('Error closing registration for election:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



// Route for opening voting for an election
app.post('/api/electionvoteopen', [authenticateToken, async(req, res) => {
    const { election_id } = req.body;

    try {
        console.log('API electionvoteopen requested');
        // Fetch current is_vote status for the election
        const fetchQuery = 'SELECT is_vote FROM election WHERE election_id = ?';
        const [rows] = await pool.execute(fetchQuery, [election_id]);

        // Check if election exists
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Election not found' });
        }

        const { is_vote } = rows[0];

        // If voting is already open, return error
        if (is_vote === 1) {
            return res.status(400).json({ error: 'Voting for this election is already open' });
        }

        // Update election to set is_vote = 1
        const updateQuery = 'UPDATE election SET is_vote = 1 WHERE election_id = ?';
        const [result] = await pool.execute(updateQuery, [election_id]);

        res.json({ success: true, message: 'Voting opened successfully' });
    } catch (error) {
        console.error('Error opening voting for election:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);



// Route for closing voting for an election
app.post('/api/electionvoteclose', [authenticateToken, async(req, res) => {
    const { election_id } = req.body;

    try {
        console.log('API electionvoteclose requested');
        // Fetch current is_vote status for the election
        const fetchQuery = 'SELECT is_vote FROM election WHERE election_id = ?';
        const [rows] = await pool.execute(fetchQuery, [election_id]);

        // Check if election exists
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Election not found' });
        }

        const { is_vote } = rows[0];

        // If voting is already closed, return error
        if (is_vote === 0) {
            return res.status(400).json({ error: 'Voting for this election is already closed' });
        }

        // Update election to set is_vote = 0
        const updateQuery = 'UPDATE election SET is_vote = 0 WHERE election_id = ?';
        const [result] = await pool.execute(updateQuery, [election_id]);

        res.json({ success: true, message: 'Voting closed successfully' });
    } catch (error) {
        console.error('Error closing voting for election:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);




// Route for voting
app.post('/api/vote', [authenticateToken, async(req, res) => {
    const { election_id, role_id, roll_no, candidate_id, gender } = req.body;

    try {
        console.log('API vote requested');

        // Convert roll_no to lowercase
        const voter_roll_no = roll_no.toLowerCase();

        // Check if the election is still open for voting
        const checkElectionQuery = 'SELECT is_vote FROM election WHERE election_id = ?';
        const [electionResult] = await pool.execute(checkElectionQuery, [election_id]);

        // Verify if the election exists and is open for voting
        if (electionResult.length === 0) {
            return res.status(404).json({ error: 'Election not found' });
        }

        const { is_vote } = electionResult[0];

        if (is_vote !== 1) {
            return res.status(400).json({ error: 'Voting for this election is closed' });
        }

        // Check if the voter has already voted in this election and role for the given gender
        const checkVoteQuery = 'SELECT * FROM vote WHERE election_id = ? AND role_id = ? AND voter_roll_no = ? AND gender = ?';
        const [existingVotes] = await pool.execute(checkVoteQuery, [election_id, role_id, voter_roll_no, gender]);

        // If a vote already exists, return an error
        if (existingVotes.length > 0) {
            return res.status(400).json({ error: 'You have already voted for this election and role' });
        }

        // Insert into the vote table
        const insertQuery = 'INSERT INTO vote (election_id, role_id, voter_roll_no, candidate_id, gender) VALUES (?, ?, ?, ?, ?)';
        const [result] = await pool.execute(insertQuery, [election_id, role_id, voter_roll_no, candidate_id, gender]);

        res.json({ success: true, message: 'Vote recorded successfully' });
    } catch (error) {
        console.error('Error recording vote:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);






// Route for getting vote results for a specific election, structured by role_id
app.post('/api/voteresult', [authenticateToken, async(req, res) => {
    const { election_id } = req.body;

    try {
        console.log('API voteresult requested');
        if (!election_id) {
            return res.status(400).json({ error: 'Election ID is required in the request body' });
        }

        // Query to get vote results for all role_ids and sorted by role_id
        const voteResultQuery = `
            SELECT v.role_id, v.candidate_id, c.reg_roll_no, c.gender, COUNT(*) as vote_count
            FROM vote v
            INNER JOIN candidate c ON v.candidate_id = c.candidate_id
            WHERE v.election_id = ?
            GROUP BY v.role_id, v.candidate_id, c.gender
            ORDER BY v.role_id, c.gender
        `;

        const [voteResults] = await pool.execute(voteResultQuery, [election_id]);

        if (voteResults.length === 0) {
            return res.status(404).json({ error: 'No vote results found for this election' });
        }

        // Query to fetch role information from roles table
        const rolesQuery = 'SELECT role_id, role_name FROM roles';
        const [roles] = await pool.execute(rolesQuery);

        // Map roles to role_id for quick lookup
        const roleMap = {};
        roles.forEach(role => {
            roleMap[role.role_id] = role.role_name;
        });

        // Query to fetch profiles and map roll_no to names
        const rollNos = voteResults.map(result => result.reg_roll_no);
        const profilesQuery = 'SELECT roll_no, name FROM profiles WHERE roll_no IN (?)';
        const [profiles] = await pool.execute(profilesQuery, [rollNos]);

        // Map roll_no to names for quick lookup
        const nameMap = {};
        profiles.forEach(profile => {
            nameMap[profile.roll_no] = profile.name;
        });

        // Calculate total votes for each role_id and gender in the election
        const totalVotesQuery = `
            SELECT role_id, gender, COUNT(*) as total_votes
            FROM vote
            WHERE election_id = ?
            GROUP BY role_id, gender
        `;
        const [totalVotesResults] = await pool.execute(totalVotesQuery, [election_id]);

        // Map the total votes to a role_id and gender indexed object
        const totalVotesMap = {};
        totalVotesResults.forEach(result => {
            if (!totalVotesMap[result.role_id]) {
                totalVotesMap[result.role_id] = {};
            }
            totalVotesMap[result.role_id][result.gender] = result.total_votes;
        });

        // Format the results by role_id with vote results nested under each gender
        const formattedResults = [];

        // Group vote results by role_id and gender
        const groupedResults = {};
        voteResults.forEach(result => {
            if (!groupedResults[result.role_id]) {
                groupedResults[result.role_id] = {
                    role_id: result.role_id,
                    role_name: roleMap[result.role_id] || 'Unknown Role',
                    gender: {}
                };
            }
            if (!groupedResults[result.role_id].gender[result.gender]) {
                groupedResults[result.role_id].gender[result.gender] = {
                    total_votes: totalVotesMap[result.role_id][result.gender] || 0,
                    vote_results: []
                };
            }
            groupedResults[result.role_id].gender[result.gender].vote_results.push({
                candidate_id: result.candidate_id,
                reg_roll_no: result.reg_roll_no,
                gender: result.gender,
                vote_count: result.vote_count,
                vote_percentage: totalVotesMap[result.role_id][result.gender] > 0 ?
                    (result.vote_count / totalVotesMap[result.role_id][result.gender]) * 100 : 0,
                name: nameMap[result.reg_roll_no] || 'Unknown'
            });
        });

        // Push grouped results into formatted array
        Object.keys(groupedResults).forEach(role_id => {
            const roleData = groupedResults[role_id];
            const roleEntry = {
                role_id: roleData.role_id,
                role_name: roleData.role_name,
                gender: []
            };
            Object.keys(roleData.gender).forEach(gender => {
                roleEntry.gender.push({
                    [gender]: {
                        total_votes: roleData.gender[gender].total_votes,
                        vote_results: roleData.gender[gender].vote_results
                    }
                });
            });
            formattedResults.push(roleEntry);
        });

        // Return the formatted results sorted by role_id
        res.json({ success: true, results: formattedResults });
    } catch (error) {
        console.error('Error fetching vote results:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }


}]);



// Route for updating SPL roles in the login table
app.post('/api/updatingsplroles', [authenticateToken, async(req, res) => {
    const { roll_no, role_id } = req.body;

    try {
        console.log('API updatingsroles requested');
        if (!roll_no || !role_id) {
            return res.status(400).json({ error: 'Roll number and role ID are required in the request body' });
        }

        // Query to update SPL role in the login table
        const updateQuery = `
            UPDATE login
            SET spl_role = ?
            WHERE roll_no = ?
        `;

        const [result] = await pool.execute(updateQuery, [role_id, roll_no]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User with the provided roll number not found' });
        }

        res.json({ success: true, message: 'SPL role updated successfully' });
    } catch (error) {
        console.error('Error updating SPL role:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
}]);


















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