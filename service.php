<?php
if(!defined('ROOT')) exit('No direct script access allowed');

if(!defined("AUTH0_DOMAIN")) {
  exit("Auth0 configuration not found for this site");
}

define("ALLOW_MAUTH",true);

require_once __DIR__ . '/vendor/autoload.php';

use Auth0\SDK\Auth0;

$auth0 = new Auth0([
  'domain' => AUTH0_DOMAIN,
  'client_id' => AUTH0_CLIENTID,
  'client_secret' => AUTH0_SECRET,
  'redirect_uri' => AUTH0_REDIRECT_URI,
  'audience' => AUTH0_AUDIENCE,
  'scope' => 'openid profile',
  'persist_id_token' => true,
  'persist_access_token' => true,
  'persist_refresh_token' => true,
//   'store' => false
]);

$userInfo = $auth0->getUser();

if (!$userInfo) {
  if(!empty($_GET['error'])) {
    if(isset($_GET['error_description'])) {
      relink($_GET['error_description']);
    } else {
      relink("Error signing in. Have you verified your email");
    }
  } else {
    $auth0->login();
  }
} else {
  loginSuccesfull($userInfo);
}

function loginSuccesfull($userLoginData) {
//   printArray($userLoginData);exit();
  doDirectLogin($userLoginData["name"]);
}

function doDirectLogin($emailID) {
  $_POST['userid'] = $emailID;
  
  $sql=_db(true)->_selectQ(_dbTable("users",true),"id, guid, userid, pwd, pwd_salt, privilegeid, accessid, groupid, name, email, mobile, region, country, zipcode, geolocation, geoip, tags, blocked, avatar, avatar_type")->_whereOR("expires",[
			"0000-00-00",["NULL","NU"],["now()","GT"]
		])->_where(["email"=>$emailID]);

  $result=$sql->_get();
  
  if(!empty($result)) {
    $data=$result[0];
    $userid = $data['userid'];
    
    if($data['blocked']=="true") {
      relink("Sorry, you are currently blocked by system admin.");
    }
    
    $accessData=_db(true)->_selectQ(_dbTable("access",true),"sites,name as access_name")->_where([
        "id"=>$data['accessid'],
        "blocked"=>"false"
      ])->_get();
    $privilegeData=_db(true)->_selectQ(_dbTable("privileges",true),"id,md5(concat(id,name)) as hash,name as privilege_name")->_where([
        "id"=>$data['privilegeid'],
        "blocked"=>"false"
      ])->_get();

    $groupData=_db(true)->_selectQ(_dbTable("users_group",true),"id,group_name,group_manager,group_descs")->_where([
        "id"=>$data['groupid']
      ])->_get();

    if(empty($accessData)) {
      relink("No Accessibilty Defined For You Or Blocked By Admin.");
    } else {
      $accessData=$accessData[0];
    }
    if(empty($privilegeData)) {
      relink("No Privileges Defined For You Or Blocked By Admin.");
    } else {
      $privilegeData=$privilegeData[0];
    }
    if(empty($groupData)) {
      $groupData="";
    } else {
      $groupData=$groupData[0];
    }

    $allSites=explode(",",$accessData['sites']);
    if($accessData['sites']=="*") {
      $allSites=getAccessibleSitesArray();
    }
    if(count($allSites)>0) {
      $_SESSION['SESS_ACCESS_SITES']=$allSites;
    } else {
      relink("No Accessible Site Found For Your UserID");
    }
    if(!in_array(SITENAME,$allSites)) {
      relink("Sorry, You [UserID] do not have access to requested site.");
    }
    
    $_ENV['AUTH-DATA']=array_merge($data,$accessData);
    $_ENV['AUTH-DATA']=array_merge($_ENV['AUTH-DATA'],$privilegeData);

    loadHelpers("mobility");

    $_ENV['AUTH-DATA']['device']=getUserDeviceType();
    $_ENV['AUTH-DATA']['client']=_server("REMOTE_ADDR");
    $_ENV['AUTH-DATA']['persistant']="false";
    $_ENV['AUTH-DATA']['sitelist']=$allSites;
    $_ENV['AUTH-DATA']['groups']=$groupData;

    $dbLink=_db(true);
    checkBlacklists($data,SITENAME,$dbLink,$userid);

    runHooks("postAuth");

    initializeLogin($userid, SITENAME);
  } else {
    relink("User Not Identified");
  }
}

function relink($msg, $link = null) {
  if($link==null) {
    $link = (SiteLocation."logout.php?site=".SITENAME);
  }
  if(!isset($_POST['userid'])) {
    $_POST['userid'] = "Guest";
  }
	_log("Login Attempt Failed","login",LogiksLogger::LOG_ALERT,[
				"userid"=>$_POST['userid'],
				"site"=>SITENAME,
				"device"=>getUserDeviceType(),
				"client_ip"=>$_SERVER['REMOTE_ADDR'],
				"msg"=>$msg]);

	$_SESSION['SESS_ERROR_MSG']=$msg;
	header("Location:{$link}");
}

//From Logiks Auth
function getAccessibleSitesArray() {
	$arr=scandir(ROOT.APPS_FOLDER);
	unset($arr[0]);unset($arr[1]);
	$out=array();
	foreach($arr as $a=>$b) {
		if(is_file(ROOT.APPS_FOLDER.$b)) {
			unset($arr[$a]);
		} elseif(is_dir(ROOT.APPS_FOLDER.$b) && !file_exists(ROOT.APPS_FOLDER.$b."/apps.cfg")) {
			unset($arr[$a]);
		} else {
			array_push($out,$b);
		}
	}
	return $out;
}
//Logging And Checking Functions
function checkBlacklists($data,$domain,$dbLink,$userid) {
	$ls=new LogiksSecurity();
	if($ls->isBlacklisted("login",$domain)) {
		relink("You are currently Blacklisted On Server, Please contact Site Admin.",$domain);
	} else {
		return false;
	}
}

//LogBook Checking
function initializeLogin($userid,$domain,$params=array()) {
	startNewSession($userid, $domain, $params);

	_log("Login Successfull @{$_SESSION['SESS_USER_ID']}","login",LogiksLogger::LOG_INFO,[
				"guid"=>$_SESSION['SESS_GUID'],
				"userid"=>$_SESSION['SESS_USER_ID'],
				"username"=>$_SESSION['SESS_USER_NAME'],
				"site"=>$domain,
				"device"=>$_ENV['AUTH-DATA']['device'],
				"client_ip"=>$_SERVER['REMOTE_ADDR']]);
	
	_db(true)->_updateQ(_dbTable("users",true),['last_login'=>date("Y-m-d H:i:s")],["guid"=>$_SESSION['SESS_GUID'],
				"userid"=>$_SESSION['SESS_USER_ID']])->_RUN();
	
	gotoSuccessLink();
}
//All session functions
function startNewSession($userid, $domain, $params=array()) {
	session_regenerate_id();
	$data=$_ENV['AUTH-DATA'];
	//printArray($data);exit();

	$_SESSION['SESS_GUID'] = $data['guid'];
	
	$_SESSION['SESS_USER_ID'] = $data['userid'];
	$_SESSION['SESS_PRIVILEGE_ID'] = $data['privilegeid'];
	$_SESSION['SESS_ACCESS_ID'] = $data['accessid'];
	$_SESSION['SESS_GROUP_ID'] = $data['groupid'];
	
	$_SESSION['SESS_PRIVILEGE_NAME'] = $data['privilege_name'];
	$_SESSION['SESS_ACCESS_NAME'] = $data['access_name'];
	$_SESSION['SESS_ACCESS_SITES'] = $data['sitelist'];

	if(empty($data['groups'])) {
		$data['groups']=[
				"id"=>0,
				"group_name"=>"",
				"group_manager"=>"",
				"group_descs"=>"",
			];
	}
	$_SESSION['SESS_GROUP_ID'] = $data['groups']['id'];
	$_SESSION['SESS_GROUP_NAME'] = $data['groups']['group_name'];
	$_SESSION['SESS_GROUP_MANAGER'] = $data['groups']['group_manager'];
	$_SESSION['SESS_GROUP_DESCS'] = $data['groups']['group_descs'];

	$_SESSION["SESS_PRIVILEGE_HASH"]=md5($_SESSION["SESS_PRIVILEGE_ID"].$_SESSION["SESS_PRIVILEGE_NAME"]);

	$_SESSION['SESS_USER_NAME'] = $data['name'];
	$_SESSION['SESS_USER_EMAIL'] = $data['email'];
	$_SESSION['SESS_USER_CELL'] = $data['mobile'];
	
	$_SESSION['SESS_USER_COUNTRY'] = $data['country'];
	$_SESSION['SESS_USER_ZIPCODE'] = $data['zipcode'];
	$_SESSION['SESS_USER_GEOLOC'] = $data['geolocation'];
	
	$_SESSION['SESS_USER_AVATAR'] = $data['avatar_type']."::".$data['avatar'];

	$_SESSION['SESS_LOGIN_SITE'] = $domain;
	$_SESSION['SESS_ACTIVE_SITE'] = $domain;
	$_SESSION['SESS_TOKEN'] = session_id();
	$_SESSION['SESS_SITEID'] = SiteID;
	$_SESSION['SESS_LOGIN_TIME'] =time();
	$_SESSION['MAUTH_KEY'] = generateMAuthKey();
	
	if($data['privilegeid']<=1) {
		$_SESSION["SESS_FS_FOLDER"]=ROOT;
		$_SESSION["SESS_FS_URL"]=SiteLocation;
	} else {
		$_SESSION["SESS_FS_FOLDER"]=ROOT.APPS_FOLDER.$domain."/";
		$_SESSION["SESS_FS_URL"]=SiteLocation.APPS_FOLDER.$domain."/";
	}

	if(strlen($_SESSION['SESS_USER_NAME'])<=0) {
		$_SESSION['SESS_USER_NAME']=$_SESSION['SESS_USER_ID'];
	}

	LogiksSession::getInstance(true);

	header_remove("SESSION-KEY");
	header("SESSION-KEY:".$_SESSION['SESS_TOKEN'],false);
	header("SESSION-MAUTH:".$_SESSION['MAUTH_KEY'],false);

	setcookie("LOGIN", "true", time()+36000,"/",null, isHTTPS());
	setcookie("USER", $_SESSION['SESS_USER_ID'], time()+36000,"/",null, isHTTPS());
	setcookie("TOKEN", $_SESSION['SESS_TOKEN'], time()+36000,"/",null, isHTTPS());
	setcookie("SITE", $_SESSION['SESS_LOGIN_SITE'], time()+36000,"/",null, isHTTPS());
	
	_db(true)->_deleteQ(_dbTable("cache_sessions",true),"created_on<DATE_SUB(NOW(), INTERVAL 1 MONTH)")->_RUN();
	
	if($data['persistant'] || (ALLOW_MAUTH && isset($_REQUEST['mauth']))) {
		_db(true)->_deleteQ(_dbTable("cache_sessions",true),"edited_on<DATE_SUB(NOW(), INTERVAL 10 DAY)")
				->_where([
				"guid"=>$_SESSION['SESS_GUID'],
				"userid"=>$_SESSION['SESS_USER_ID'],
				"site"=>$domain,
			])->_RUN();
		_db(true)->_insertQ1(_dbTable("cache_sessions",true),[
				"guid"=>$_SESSION['SESS_GUID'],
				"userid"=>$_SESSION['SESS_USER_ID'],
				"site"=>$domain,
				"device"=>$_ENV['AUTH-DATA']['device'],
				"session_key"=>$_SESSION['SESS_TOKEN'],
				"auth_key"=>$_SESSION['MAUTH_KEY'],
				"session_data"=>json_encode($_SESSION),
				"global_data"=>json_encode($GLOBALS),
				"client_ip"=>$_SERVER['REMOTE_ADDR'],
				"created_by"=>$_SESSION['SESS_USER_ID'],
				"edited_by"=>$_SESSION['SESS_USER_ID'],
			])->_RUN();
	}
}
function logoutOldSessions($userid, $domain, $params=array()) {
	_db(true)->_deleteQ(_dbTable("cache_sessions",true),[
				"guid"=>$_SESSION['SESS_GUID'],
				"userid"=>$_SESSION['SESS_USER_ID'],
				"site"=>$domain,
			])->_RUN();
}

function gotoSuccessLink() {
	$onsuccess=_link("home");
  

	$domain=$_SESSION['SESS_ACTIVE_SITE'];//ACTIVE
	if(ALLOW_MAUTH) {
    if(isset($_REQUEST['mauth'])) {
      if($_REQUEST['mauth']=="authkey") {
        echo $_SESSION['MAUTH_KEY'];
      } elseif($_REQUEST['mauth']=="jwt") {
        $arr=array(
            "guid"=>$_SESSION['SESS_GUID'],
            "username"=>$_SESSION['SESS_USER_NAME'],

            "user"=>$_SESSION['SESS_USER_ID'],
            "mobile"=>$_SESSION['SESS_USER_CELL'],
            "email"=>$_SESSION['SESS_USER_EMAIL'],
            "country"=>$_SESSION['SESS_USER_COUNTRY'],

            "privilegeid"=>$_SESSION['SESS_PRIVILEGE_ID'],
            "privilege_name"=>$_SESSION['SESS_PRIVILEGE_NAME'],
            "accessid"=>$_SESSION['SESS_ACCESS_ID'],
            "groupid"=>$_SESSION['SESS_GROUP_ID'],
            "access"=>$_SESSION['SESS_ACCESS_SITES'],

            "timestamp"=>date("Y-m-d H:i:s"),
            "site"=>$domain,
            "client"=>_server('REMOTE_ADDR'),
            "authkey"=>$_SESSION['MAUTH_KEY'],
            //"token"=>$_SESSION['SESS_TOKEN'],

            "avatar"=>$_SESSION['SESS_USER_AVATAR'],
          );
          $jwt = new LogiksJWT();
          $jwtToken = $jwt->generateToken($arr);
          header("Content-Type:text/json");
          echo json_encode(["token"=>$jwtToken,"msg"=>"Login Success","status"=>'success']);
      } elseif($_REQUEST['mauth']=="jsonkey") {
        $arr=array(
            "user"=>$_SESSION['SESS_USER_ID'],
            "mobile"=>$_SESSION['SESS_USER_CELL'],
            "email"=>$_SESSION['SESS_USER_EMAIL'],
            "country"=>$_SESSION['SESS_USER_COUNTRY'],

            "date"=>date("Y-m-d"),
            "time"=>date("H:i:s"),
            "site"=>$domain,
            "client"=>_server('REMOTE_ADDR'),
            "authkey"=>$_SESSION['MAUTH_KEY'],
//             "token"=>$_SESSION['SESS_TOKEN'],

            "username"=>$_SESSION['SESS_USER_NAME'],
            "avatar"=>$_SESSION['SESS_USER_AVATAR'],
          );
        header("Content-Type:text/json");
        echo json_encode($arr);
      } else {
        echo $_SESSION['MAUTH_KEY'];
      }
    } else {
      echo "<h5>Securing Access Authentication ... </h5>";
			if(strlen($onsuccess)==0 || $onsuccess=="*")
				header("location: ".SiteLocation."?site=$domain");
			else {
				if(substr($onsuccess,0,7)=="http://" || substr($onsuccess,0,8)=="https://" ||
					substr($onsuccess,0,2)=="//" || substr($onsuccess,0,2)=="./" || substr($onsuccess,0,1)=="/") {
						header("location: $onsuccess");
				}
			}
    }
	} else {
		//echo "<h5>Securing Access Authentication ... </h5>";
		if(strlen($onsuccess)==0 || $onsuccess=="*") {
			header("location: "._link(getConfig("PAGE_HOME")));
		} else {
			if(substr($onsuccess,0,7)=="http://" || substr($onsuccess,0,8)=="https://" ||
				substr($onsuccess,0,2)=="//" || substr($onsuccess,0,2)=="./" || substr($onsuccess,0,1)=="/") {
					header("location: $onsuccess");
			}
		}
	}
	exit();
}
?>