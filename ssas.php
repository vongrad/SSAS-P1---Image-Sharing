<?php

require_once('vendor/autoload.php');
use \Firebase\JWT\JWT;

date_default_timezone_set('Europe/Copenhagen');

class Ssas {

    /**
     * Database host
     * @var
     */
    private $mysqliServer;
    /**
     * Database user
     * @var
     */
    private $mysqliUser;
    /**
     * Database password
     * @var string
     */
    private $mysqliPass;
    /**
     * Database name
     * @var string
     */
    private $mysqliDb;
    /**
     * JWT encoding key
     * @var string
     */
    private $key;
    private $data;
    /**
     * Location of uploaded files
     * @var string
     */
    public static $path_uploads = "/uploads/";

    /**
     * MySQLi link to the databse for executing queries
     * @var mysqli
     */
    private $db_link;

    function __construct(){

        // Load config file
        $config = json_decode(file_get_contents(dirname(__FILE__).'/config.json'));

        // DB set-up
        $this->mysqliServer = $config->db_host;
        $this->mysqliUser = $config->db_user;
        $this->mysqliPass = $config->db_pass;
        $this->mysqliDb = $config->db_name;

        // JWT key
        $this->key = $config->secret;

        // Set up connection to the databse
        $this->db_link = mysqli_connect($this->mysqliServer, $this->mysqliUser, $this->mysqliPass, $this->mysqliDb);
    }

    /**
     * Helper function for execution MySQL SELECT queries
     * @param $query - SQL query with placeholders for values
     * @param $params - array('types' => '...', 'values' => '...'))
     * @return bool|mysqli_result
     */
	function execute_select($query, $params) {

        $stmt = $this->db_link->prepare($query);

        call_user_func_array(array($stmt, 'bind_param'), array_merge(array($params['types']), $params['values']));

        $stmt->execute();

        return $stmt->get_result();
    }

    /**
     * Helper function for execution MySQL INSERT/UPDATE/DELETE queries
     * @param $query
     * @param $params
     * @return int
     */
    function execute_update($query, $params) {
        $stmt = $this->db_link->prepare($query);

        call_user_func_array(array($stmt, 'bind_param'), array_merge(array($params['types']), $params['values']));

        $stmt->execute();

        return $stmt->affected_rows;
    }

    // This function will authenticate a user based on the token cookie.
    // returns true if the user is authenticated, otherwise return false
    // if the token is invalid or has expired the method will call exit() and not return anything
    function authenticate(){
        if(isset($_COOKIE['token'])){
            try{
                //Retrieves the JWT token from the cookie
                $token = $_COOKIE['token'];

                //Decrypts the token. This call will throw an exception if the token is invalid
                $token = (array) JWT::decode($token, $this->key, array('HS512'));

                //Extracts the user data from the token
                $this->data = (array) $token['data'];

				//Check that the user actually exists (could have been removed)
				$uid = $this->getUid();
				$username = $this->getUsername();

                $params = array('types' => 'is', 'values' => array(&$uid, &$username));
                $query = 'SELECT id FROM user WHERE id = ? AND username = ?';

                $result = $this->execute_select($query, $params);

                if ($result->num_rows == 1) return true;

                //If the query did not succeed, then there is something wrong!
                throw new Exception('Authentication failed!');

            } catch (Exception $e){

                //This will happend if
                //  1) The token has expired
                //  2) The token is not valid
                //  3) No user matching the user data exists

                $this->logout();
                header("Location: index.php");
                exit(); //Just to be sure

            }
        }
       return false; //Could not authenticate
    }

    // This function will destroy the token cookie if it exists
    function logout(){
        if(isset($_COOKIE['token'])){
            unset($_COOKIE['token']);
            setcookie('token', '', time() - 3600);
        }
    }

    // This function will check if the user is logged in
    // If the user is not authenticated, the the method will try to authenticate.
    // returns true if the user is logged in otherwise false
    function isUserLoggedIn(){
        if(!isset($this->data) && isset($_COOKIE['token'])) $this->authenticate();
        return isset($this->data);
    }

    // This function will return to logged in users id (if authenticated)
    function &getUid(){
        if($this->isUserLoggedIn()) return $this->data['uid'];
    }

    // This function will return to logged in users username (if authenticated)
    function &getUsername(){
        if($this->isUserLoggedIn()) return $this->data['username'];
    }

    // This function will create a new user with the given username password combo
    // returns true if the user was created, otherwise error message
    function createUser($username, $password){
        if($username == "") return "username can't be empty";
        if($password == "") return "password can't be empty";

		// Prepare salt and hashed password
        $salt = $this->generate_salt();
        $hash = $this->hash_password($password, $salt);

        //Inserts username and password into the database
        $params = array('types' => 'sss', 'values' => array(&$username, &$hash, &$salt));
        $query = 'INSERT INTO user(username, password, salt) VALUES (?, ?, ?)';

        if($this->execute_update($query, $params) == 1) {
            return true;
        }

		//If exactly one row was affected then we know that the user was inserted.
        return "user could not be created";
    }

    // This function will login with the given username password combo
    // returns true if the login was successful, otherwise error message
    function login($username, $password){

        $params = array('types' => 's', 'values' => array(&$username));
        //Query to get the username and real password,
        $query = 'SELECT id, password, salt FROM user WHERE username = ?';

        $result = $this->execute_select($query, $params);

        if($result->num_rows != 1) {
            return "username and password does not match";
        }

        $row = mysqli_fetch_assoc($result);

        $uid = $row['id'];
        $hash = $row['password'];
        $salt = $row['salt'];

        if(!hash_equals($hash, $this->hash_password($password, $salt))) {
            return "username and password does not match";
        }

        //Generates random token_id
        $tokenId = base64_encode(mcrypt_create_iv(32, MCRYPT_DEV_URANDOM));

        $issuedAt = time();
        $expire = $issuedAt + 3600; // token expires in 60 minutes
        $data = [
            'iat' => $issuedAt,
            'jti' => $tokenId,
            'nbf' => $issuedAt,
            'exp' => $expire,
            'data' => [
                'uid' => $uid,
                'username' => $username
            ]
        ];

        // Computes the encrypted token
        $jwt = JWT::encode($data, $this->key, 'HS512');

        // Sets to cookie to never expire as the token itself contains the expiration date (Mimimum exposure)
        setcookie("token", $jwt, -1);
        return true;
    }

    // This function uploads the given image
    // returns true if the image was successfully uploaded, otherwise error message.
    function uploadImage($filename, $data){
        if($this->isUserLoggedIn()){

            $uid = $this->getUid();

			$query = 'INSERT INTO image(owner_id) VALUES(?)';
            $params = array('types' => 'i', 'values' => array(&$uid));

            if($this->execute_update($query, $params) == 1) {
				$iid = mysqli_insert_id($this->db_link);
                $filename = "{$iid}_{$filename}";

                $query = "UPDATE image SET filename = ? WHERE id = ?";
                $params = array('types' => 'si', 'values' => array(&$filename, &$iid));

                $this->execute_update($query, $params);

                $this->save_image($filename, $data);
				return true;
			}            
			return "Image could not be uploaded";
        }
        return "Image could not be uploaded2";
    }



    /**
     * Get file extension
     * @param $filename
     * @return string extension
     */
    private function getExtension($filename) {
        return substr($filename, strrpos($filename, '.'));
    }

    // This function will lookup a users id given the username
    // returns the user id if exists, otherwise false
    private function getUserId($username){

//		$query = "SELECT id FROM user WHERE username = '".$username."';";

        $query = 'SELECT id FROM user WHERE username = ?';
        $params = array('types' => 's', 'values' => array(&$username));

        $result = $this->execute_select($query, $params);

		if ($result->num_rows > 0) {
			$row = mysqli_fetch_assoc($result);
			return $row['id'];
		}
        return false;
    }

    // This function will remove sharing with the given user for the given image
    // returns true if the operation was successful, otherwise false
    function removeShare($iid, $username){

        if($this->isUserLoggedIn() && $this->isOwner($iid)){
            $uid = $this->getUserId($username);
            if($uid == false) return false;

            //Removing sharing of image from database
			$query = 'DELETE FROM shared_image WHERE image_id = ? AND user_id = ?';
            $params = array('types' => 'ii', 'values' => array(&$iid, &$uid));

			return $this->execute_update($query, $params) == 1;
        }
        return false;
    }

    // This function will share the given image with the given user
    // returns true if the image was shared, otherwise false
    function shareImage($iid, $username)
    {
        //The user must be owner of the image to share it
        if($this->isUserLoggedIn() && $this->isOwner($iid)){

            //Getting uid from username
            $uid = $this->getUserId($username);

            //Inserting sharing of image into database
			$query = 'INSERT INTO shared_image VALUES (?, ?)';
            $params = array('types' => 'ii', 'values' => array(&$uid, &$iid));

			return $this->execute_update($query, $params) == 1;
        }
		return false;
    }

    // This function returns a list of users whom the given image can be shared with
    // returns a list of users if successful, otherwise false
    function getUsersToShareWith($iid){
        if($this->isUserLoggedIn()){//&& $this->isOwner($iid)){
            $users = array();

			// Query database for users to share with, which is everyone but the owner 
			// and those whom the image is already shared with.
			$uid = $this->getUid();

            $query = 'SELECT id,username FROM user WHERE id <> ? AND id NOT IN (SELECT user_id FROM shared_image WHERE image_id = ?)';
            $params = array('types' => 'ii', 'values' => array(&$uid, &$iid));

            $result = $this->execute_select($query, $params);

			if ($result->num_rows > 0) {
				while ($row = mysqli_fetch_assoc($result)) {
					$users[] = new user($row['id'], $row['username']);
				}
		    } else {
		        return "No users to share this with.";
		    }			

            return $users;
        }
        return false;
    }

    // This function returns a list of users whom the given image is shared with.
    // returns a list of users if successful, otherwise false
    function sharedWith($iid){
        if($this->isUserLoggedIn()) {
            $users = array();
			
			$query = 'SELECT id,username FROM user INNER JOIN shared_image ON id = user_id WHERE image_id = ?';
            $params = array('types' => 'i', 'values' => array(&$iid));

            $result = $this->execute_select($query, $params);

			if ($result->num_rows > 0) {
				while ($row = mysqli_fetch_assoc($result)) {
					$users[] = new user($row['id'], $row['username']);
				}
		    }

            return $users;
        }
        return false;
    }

	// This function saves the image to a file with the corresponding image id as the name.
	function save_image($filename, $data){
		$file = dirname(__FILE__).Ssas::$path_uploads.$filename;
		file_put_contents($file, $data);
	}

	// This function loads the image file with the corresponding image id.
	function loadImage($filename){
		$file = dirname(__FILE__).Ssas::$path_uploads.$filename;
		$type = pathinfo($file, PATHINFO_EXTENSION);
		$data = file_get_contents($file);
		$img = 'data:image/' . $type . ';base64,' . base64_encode($data);		
		return $img;
	}

    // This function returns a list of all images shared with the loggedin user
    // returns a list of images if successful, otherwise false
    function getImages(){
        if($this->isUserLoggedIn()){
            $images = array();
			
			// The images to display should either be those owned by the user
			// or those ahred with the user and should not be duplicated.
			$uid = $this->getUid();
			$query = 'SELECT DISTINCT image.id,owner_id,username,createdDate,filename
              FROM image INNER JOIN user on user.id = owner_id 
              LEFT JOIN shared_image ON image_id = image.id 
              WHERE user_id = ? OR owner_id = ? ORDER BY createdDate DESC';

            $params = array('types' => 'ii', 'values' => array(&$uid, &$uid));

            $result = $this->execute_select($query, $params);

			if ($result->num_rows > 0) {
				while ($row = mysqli_fetch_assoc($result)) {
					$iid = $row['id'];
					$images[] = new Image($iid, $row['owner_id'], $row['username'], $row['createdDate'], $row['filename']);
				}
		    }

            return $images;
        }
        return false;
    }

    // This function returns the given image iff the loggedin user have access to it
    // returns the image if successful, otherwise false
    function getImage($iid)
    {
        if($this->isUserLoggedIn())
        {
			$uid = $this->getUid();
			$query = 'SELECT image.id,owner_id,username,createdDate,filename 
              FROM image INNER JOIN user ON user.id = owner_id 
              LEFT JOIN shared_image ON image_id = image.id 
              WHERE (user_id = ? OR owner_id = ?) AND image.id = ?';

            $params = array('types' => 'iii', 'values' => array(&$uid, &$uid, &$iid));

            $result = $this->execute_select($query, $params);
			
			if ($result->num_rows > 0) {
				$row = mysqli_fetch_assoc($result);
			
				return new Image($iid, $row['owner_id'], $row['username'], $row['createdDate'], $row['filename']);
			}
			return null;
        }

        return false;
    }

    // This function will post given comment to given image iff the loggedin user has access to post
    // returns true if successful, otherwise false
    function comment($iid, $comment)
    {
        if($this->isUserLoggedIn() && $this->verifyShare($this->getUid(), $iid))
        {
			$uid = $this->getUid();

            $query = 'INSERT INTO post(text, user_id, image_id) VALUES (?, ?, ?)';
            $params = array('types' => 'sii', 'values' => array(&$comment, &$uid, &$iid));

			return $this->execute_update($query, $params) == 1;
        }
        return false;
    }

    // This function gets all comments for the given image
    // returns a list of comments if successful, otherwise false
    function getComments($iid)
    {
        if($this->isUserLoggedIn() && $this->verifyShare($this->getUid(), $iid))
      	{			
            $comments = array();

			$query = 'SELECT post.id,username,text,createdDate FROM post INNER JOIN user ON user_id = user.id WHERE image_id = ? ORDER BY createdDate ASC';
            $params = array('types' => 'i', 'values' => array(&$iid));

            $result = $this->execute_select($query, $params);

			if ($result->num_rows > 0) {
				while ($row = mysqli_fetch_assoc($result)) {
					// Only include verified comments
					$text = $row['text'];
                    $comments[] = new Comment($row['id'], $row['username'], $text, $row['createdDate']);
				}
		    }

            return $comments;
        }
        return false;
    }

    // This function checks if the loggedin user is owner of the given image
    // returns true if the loggedin user is owner, otherwise false
    function isOwner($iid){
		$uid = $this->getUid();

		$query = 'SELECT id FROM image WHERE owner_id = ? AND id = ?';
        $params = array('types' => 'ii', 'values' => array(&$uid, &$iid));

        $result = $this->execute_select($query, $params);
		return $result->num_rows > 0;
    }

    // This function checks if the loggedin user is either owner or has access to the given image
    // returns true if the loggedin user has access, otherwise false
    function verifyShare($uid, $iid)
    {
		$query = 'SELECT id FROM image LEFT JOIN shared_image ON image_id = id WHERE (user_id = ? OR owner_id = ?) AND id = ?';
        $params = array('types' => 'iii', 'values' => array(&$uid, &$uid, &$iid));

        $result = $this->execute_select($query, $params);
		return $result->num_rows > 0;
    }

    /**
     * Generate hash of the password concatenated with a salt
     * @param $password
     * @param $salt
     * @return string
     */
    function hash_password($password, $salt) {
        return crypt($password, $salt);
    }

    /**
     * Generate salt for a specific user
     * Should happen upon registration
     * @return string
     */
    function generate_salt(){
        $salt = strtr(base64_encode(mcrypt_create_iv(16, MCRYPT_DEV_URANDOM)), '+', '.');
        return sprintf("$2a$%02d$", 10) . $salt;
    }
}

class User{
    private $_id;
    private $_name;

    public function __construct($id, $name){
        $this -> _id = $id;
        $this -> _name = $name;
    }

    public function getName(){ return htmlspecialchars($this -> _name, ENT_QUOTES, 'UTF-8'); }
    public function getId(){ return $this -> _id; }
}

// This class is kind of obsolete, but still used.
// Might be used in the future to, like, maybe store images in a database?
class Image{

    private $_id;
    private $_ownerId;
    private $_image;
    private $_username;
    private $_datetime;
    private $_filename;

    public function __construct($id, $ownerId, $username, $datetime, $filename){
        $this -> _id = $id;
        $this -> _ownerId = $ownerId;
        $this -> _username = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
        $this -> _datetime = new DateTime($datetime);
        $this->_filename = $filename;
    }

    public function getUrl() { return dirname(__FILE__).Ssas::$path_uploads."{$this->_filename}"; }
    public function getId() { return $this -> _id; }
    public function getOwnerId() { return $this -> _ownerId; }
    public function getUser() { return $this -> _username; }
    public function getImage() { return $this -> _image; }
    public function getAge() {
        $date = $this -> _datetime;
        $currentDate = new DateTime();
        $dateDiff = $date -> diff($currentDate);
        $years = $dateDiff -> y;
        $months = $dateDiff -> m;
        $days = $dateDiff -> d;
        $hours = $dateDiff -> h;
        $minutes = $dateDiff -> i;
        $seconds = $dateDiff -> s;


        if($years > 1) return $years .' years';
        if($years > 0) return $years .' year';
        if($months > 1) return $months .' months';
        if($months > 0) return $months .' month';
        if($days > 1) return $days .' days';
        if($days > 0) return $days .' day';
        if($hours > 1) return $hours .' hours';
        if($hours > 0) return $hours .' hour';
        if($minutes > 1) return $minutes .' minutes';
        if($minutes > 0) return $minutes .' minute';
        if($seconds > 1) return $seconds .' seconds';
        if($seconds >= 0) return $seconds .' second';
        return "Error!";
    }
    public function get_filename() { return $this->_filename; }
}

class Comment{
    private $_id;
    private $_userName;
    private $_text;
    private $_datetime;

    public function __construct($id, $userName, $text, $datetime){
        $this -> _id = $id;
        $this -> _userName = htmlspecialchars($userName, ENT_QUOTES, 'UTF-8');
        $this -> _text = htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
        $this -> _datetime = new DateTime($datetime);
    }

    public function getId() { return $this -> _id; }
    public function getUser() { return $this -> _userName; }
    public function getText() { return $this -> _text; }
    public function getAge() {
        $date = $this -> _datetime;
        $currentDate = new DateTime();
        $dateDiff = $date -> diff($currentDate);
        $years = $dateDiff -> y;
        $months = $dateDiff -> m;
        $days = $dateDiff -> d;
        $hours = $dateDiff -> h;
        $minutes = $dateDiff -> i;
        $seconds = $dateDiff -> s;


        if($years > 1) return $years .' years';
        if($years > 0) return $years .' year';
        if($months > 1) return $months .' months';
        if($months > 0) return $months .' month';
        if($days > 1) return $days .' days';
        if($days > 0) return $days .' day';
        if($hours > 1) return $hours .' hours';
        if($hours > 0) return $hours .' hour';
        if($minutes > 1) return $minutes .' minutes';
        if($minutes > 0) return $minutes .' minute';
        if($seconds > 1) return $seconds .' seconds';
        if($seconds >= 0) return $seconds .' second';
        return "Error!";
    }
}
