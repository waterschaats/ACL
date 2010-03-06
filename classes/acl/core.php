<?php

/* ------------------------------------------------------
 * New to ACL? Read the Zend documentation:
 *   http://framework.zend.com/manual/en/zend.acl.html
 * All their examples work with this lib
 * ------------------------------------------------------
 *
 * This is a Kohana port of the Zend_ACL library, with a few changes.
 *
 * Things that are different from Zend_ACL:
 * 1) Your ACL definition is saved using the string identifiers of the roles/resources,
 *    NOT the objects. This way, if you serialize the ACL, you won't end up with a 
 *    unneccesary large serialization string. You don't have to supply objects when
 *    adding roles/resources. EG a $acl->add_role('user') is fine.
 * 2) If you have defined assertions in your rules, the assert methods will have access
 *    to the arguments you provided in the ->allow($role,$resource,$privilege) call.
 *    So, if you provide a User_Model as $role, the assert method will receive this object,
 *    and not the role_id of this object. This way, assertions become way more powerful.
 * 3) Not all methods are implemented, because they weren't needed by me at the time.
 *    However, the essential methods (the core of ACL) are implemented, so the missing methods
 *    can be implemented easily when needed.
 * 4) The methods are underscored instead of camelCased, so add_role, add_resource and is_allowed.
 *
 * Ported to Kohana & modified by Wouter - see Kohana Forum.
 *
 * Based on Zend_Acl:
 *
 * @category   Zend
 * @package    Zend_Acl
 * @copyright  Copyright (c) 2005-2008 Zend Technologies USA Inc. (http://www.zend.com)
 * @license    http://framework.zend.com/license/new-bsd     New BSD License
 * @version    $Id: Acl.php 9417 2008-05-08 16:28:31Z darby $
 */

abstract class Acl_Core {
	
	protected $command = array();

	protected $_roles = array();
	protected $_resources = array();

	protected $_rules = array();
	/* the $_rules array is structured in a way like this:
	array(
		'allResources' => array(
			'allRoles' => array(
				'allPrivileges' => array(
					'allow'  => FALSE,
					'assert' => null
				),
				'byPrivilegeId' => array()
			),
			'byRoleId' => array()
		),
		'byResourceId' => array()
	);
  */

	// add role
	public function add_role($role,$parents = NULL)
	{
		if ( $parents !== NULL && ! is_array($parents))
		{
			$parents = array($parents);
		}

		$this->_roles[$role] = array(
			'children' => array(),
			'parents'  => $parents
		);

		if ( ! empty($parents))
		{
			foreach ( $parents as $parent)
			{
				$this->_roles[$parent]['children'][] = $role;
			}
		}
	}

	// check if role exists in ACL
	public function has_role($role)
	{
		return $role !== NULL && isset($this->_roles[$role]);
	}

	// add resource
	public function add_resource($resource,$parent = NULL)
	{
		$this->_resources[$resource] = array(
			'children' => array(),
			'parent'   => $parent
		);

		if ( $parent !== NULL)
		{
			$this->_resources[$parent]['children'][] = $resource;
		}
	}

	// check if resource exists in ACL
	public function has_resource($resource)
	{
		return $resource !== NULL && isset($this->_resources[$resource]);
	}

	// add an allow rule
	public function allow($roles = NULL, $resources = NULL, $privileges = NULL, Acl_Assert_Interface $assertion = NULL)
	{
		$this->add_rule(TRUE,$roles,$resources,$privileges,$assertion);
	}

	// add an deny rule
	public function deny($roles = NULL, $resources = NULL, $privileges = NULL, Acl_Assert_Interface $assertion = NULL)
	{
		$this->add_rule(FALSE,$roles,$resources,$privileges,$assertion);
	}

	// internal add rule method
	private function add_rule($allow,$roles,$resources,$privileges,$assertion)
	{
		// Normalize arguments (build arrays with IDs as string)

		//privileges
		if ( $privileges !== NULL && !is_array($privileges)) 
		{
			$privileges = array($privileges);
		}

		//resources
		if ( $resources !== NULL)
		{
			if ( ! is_array($resources)) 
			{
				$resources = array($resources);
			}
			foreach ( $resources as &$resource)
			{
				if ( $resource instanceof Acl_Resource_Interface)
				{
					$resource = $resource->get_resource_id();
				}
				else
				{
					$resource = (string) $resource;
				}
			}
		}

		//roles
		if ( $roles !== NULL)
		{
			if ( ! is_array($roles)) 
			{
				$roles = array($roles);
			}

			foreach ( $roles as &$role)
			{
				if ( $role instanceof Acl_Role_Interface)
				{
					$role = $role->get_role_id();
				}
				else
				{
					$role= (string) $role;
				}
			}
		}

		// start building rule, from bottom to top
		$rule = array(
			'allow'	 => $allow,
			'assert' => $assertion
		);

		$rule = $privileges === NULL 
			? array('allPrivileges' => $rule) 
			: array('byPrivilegeId'=> array_fill_keys($privileges,$rule));

		$rule = $roles === NULL 
			? array('allRoles' => $rule) 
			: array('byRoleId' => array_fill_keys($roles,$rule));

		$rule = $resources === NULL 
			? array('allResources' => $rule) 
			: array('byResourceId' => array_fill_keys($resources,$rule));

		// using arr::merge, this appends numeric keys, but replaces associative keys
		$this->_rules = arr::merge($this->_rules,$rule);
	}

	public function is_allowed($role = NULL, $resource = NULL, $privilege = NULL)
	{
		// save command data (in case of assertion, then the original objects are used)
		$this->command = array
		(
			'role'      => $role,
			'resource'  => $resource,
			'privilege' => $privilege
		);

		// normalize role
		$roles = $role !== NULL 
			? ($role instanceof Acl_Role_Interface ? $role->get_role_id() 
			: (is_array($role) ? $role : (string) $role)) : NULL;

		// make array (we support checking multiple roles at once, the first matching rule for any of the roles will be returned)
		if( ! is_array($roles))
		{
			$roles = array($roles);
		}

		// normalize resource to a string value (or NULL)
		$resource = $resource !== NULL
			? ($resource instanceof Acl_Resource_Interface ? $resource->get_resource_id() : (string) $resource)
			: NULL;

		// resource unknown
		if( $resource !== NULL && !$this->has_resource($resource))
		{
			return FALSE;
		}

		// loop for matching rule
		do
		{
			if ( $rule = $this->_find_match_role($resource,$roles,$privilege))
			{
				return $rule['allow'];
			}
		}
		// go level up in resources tree (child resources inherit rules from parent)
		while ( $resource !== NULL AND ($resource = $this->_resources[$resource]['parent']));

		return FALSE;
	}

	/*
	 * Try to find a matching rule based for supplied role and its parents (if any)
	 *
	 * @param string $resource  resource id
	 * @param array  $roles     array of role ids
	 * @param string $privilege privilege
	 * @return array|boolean a matching rule on success, false otherwise.
	 */
	private function _find_match_role($resource,$roles,$privilege)
	{
		foreach ( $roles as $role)
		{
			// role unknown - skip
			if( $role !== NULL && !$this->has_role($role))
			{
				continue;
			}

			// find match for this role
			if ( $rule = $this->_find_match($this->_rules,$resource,$role,$privilege))
			{
				return $rule;
			}
			
			// try parents of role (starting at last added parent role)
			if ( $role !== NULL && !empty($this->_roles[$role]['parents']))
			{
				// let's see if any of the parent roles for this role return a valid rule
				if ( $rule = $this->_find_match_role($resource,array_reverse($this->_roles[$role]['parents']),$privilege))
				{
					return $rule;
				}
			}
		}

		return FALSE;
	}
	
	/*
	 * Try to find a matching rule based on the specific arguments
	 *
	 * @param array  $attach    the (remaining) rules array
	 * @param string $resource  resource id
	 * @param string $role      role id
	 * @param string $privilege privilege
	 * @return array|boolean a matching rule on success, false otherwise.
	 */
	private function _find_match(& $attach,$resource,$role,$privilege)
	{
		//echo Kohana::debug($resource,$role,$privilege);

		// resource level
		if($resource !== FALSE)
		{
			if ( isset($attach['byResourceId'][$resource]) && ($rule = $this->_find_match($attach['byResourceId'][$resource],FALSE,$role,$privilege)))
			{
				return $rule;
			}
			elseif ( isset($attach['allResources']))
			{
				$attach =& $attach['allResources'];
			}
			else
			{
				return FALSE;
			}
		}

		// role level
		if ( $role !== FALSE)
		{
			if ( isset($attach['byRoleId'][$role]) && ($rule = $this->_find_match($attach['byRoleId'][$role],FALSE,FALSE,$privilege)))
			{
				return $rule;
			}
			elseif ( isset($attach['allRoles']))
			{
				$attach =& $attach['allRoles'];
			}
			else
			{
				return FALSE;
			}
		}

		if ( $privilege === NULL)
		{
			// No privilege specified = check for all privileges

			if ( isset($attach['byPrivilegeId']))
			{
				foreach ( $attach['byPrivilegeId'] as $rule)
				{
					// If one specific privilege is denied, then not all privileges are allowed
					if ( $this->_rule_runnable($rule,FALSE))
					{
						return $rule;
					}
				}
			}

			// No specific privileges are denied, check all privileges rule
			if ( ! empty($attach['allPrivileges']) && $this->_rule_runnable($attach['allPrivileges']))
			{
				return $attach['allPrivileges'];
			}

			// No rule found
			else
			{
				return FALSE;
			}
		}
		else
		{
			// Privilege defined - check if privilege specific rule is set and runnable
			if ( isset($attach['byPrivilegeId'][$privilege]) && $this->_rule_runnable($attach['byPrivilegeId'][$privilege]))
			{
				return $attach['byPrivilegeId'][$privilege];
			}

			// No specific rule for privilege, fallback to allPrivileges rule
			elseif ( ! empty($attach['allPrivileges']) && $this->_rule_runnable($attach['allPrivileges']))
			{
				return $attach['allPrivileges'];
			}

			// No rule found
			else
			{
				return FALSE;
			}
		}

		// never reached
		return FALSE;

	}

	/*
	 * Verifies if rule can be applied to specified arguments
	 *
	 * @param  array   $rule  the rule
	 * @param  boolean $allow verify if rule is allowing/denying
	 * @return boolean rule can be applied to arguments
	 */
	private function _rule_runnable($rule,$allow = NULL)	
	{
		if ( $allow !== NULL)
		{
			if ( $rule['allow'] !== $allow)
			{
				return FALSE;
			}
		}

		if ( isset($rule['assert']))
		{
			return $rule['assert']->assert($this,$this->command['role'],$this->command['resource'],$this->command['privilege']);
		}

		return TRUE;
	}

	public function __sleep()
	{
		return array('_roles','_resources','_rules'); // no need to save the current command ($this->command)
	}
}