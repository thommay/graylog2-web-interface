module LdapAuthentication
  def self.extended(base_class)
    base_class.extend(LdapAuthentication::ClassMethods)
    base_class.class_eval do
      class << self
        alias_method_chain :authenticate, :ldap
      end

      field :from_ldap, :type => Boolean, :default => false

      attr_accessible :from_ldap
    end
  end

  module ClassMethods
    def authenticate_with_ldap(login, password)
      authenticated_user = ldap_login(login, password)

      if authenticated_user
        password = "not needed for ldap"
        user     = find_or_create_by_login!(login, { :email                 => authenticated_user.mail.first,
                                                     :name                  => authenticated_user.try(::Configuration.ldap_displayname_attribute.to_sym).first,
                                                     :password              => password,
                                                     :password_confirmation => password,
                                                     :role                  => User::STANDARD_ROLE,
                                                     :from_ldap             => true })

        # Use the most recent information from LDAP
        user.update_attributes!(:email => authenticated_user.mail.first,
                                :name  => authenticated_user.try(::Configuration.ldap_displayname_attribute.to_sym).first)
        user
      else
        authenticate_without_ldap(login, password)
      end
    end

    private
    # Returns a single Net::LDAP::Entry or false
    def ldap_login(username, password)
      ldap_session       = new_ldap_session
      bind_args          = args_for(username, password)
      authenticated_user = ldap_session.bind_as(bind_args)

      authenticated_user ? authenticated_user.first : false
    end

    # This is where LDAP jumps up and punches you in the face, all the while
    # screaming "You never gunna get this, your wasting your time!".
    def args_for(username, password)
      user_filter = "#{ ::Configuration.ldap_username_attribute }=#{ username }"
      args        = { :base     => ::Configuration.ldap_base,
                      :filter   => "(#{ user_filter })",
                      :password => password }

      unless ::Configuration.ldap_can_search_anonymously?
        # If you can't search your LDAP directory anonymously we'll try and
        # authenticate you with your user dn before we try and search for your
        # account (dn example. `uid=clowder,ou=People,dc=mycompany,dc=com`).
        user_dn = [user_filter, ::Configuration.ldap_base].join(',')
        args.merge({ :auth => { :username => user_dn, :password => password, :method => :simple } })
      end

      args
    end

    def new_ldap_session
      Net::LDAP.new(:host       => ::Configuration.ldap_host,
                    :port       => ::Configuration.ldap_port,
                    :encryption => ::Configuration.ldap_encryption.try(:to_sym),
                    :base       => ::Configuration.ldap_base)
    end

  end

  module Configuration
    def ldap_config(key, default = nil)
      nested_general_config :ldap, key, default
    end

    def ldap_enabled?
      ldap_config :enabled, false
    end

    def ldap_host
      ldap_config :host
    end

    def ldap_port
      ldap_config :port, 389
    end

    def ldap_base
      ldap_config :base
    end

    def ldap_encryption
      ldap_config :encryption
    end

    def ldap_displayname_attribute
      ldap_config :displayname_attribute, :displayname
    end

    def ldap_username_attribute
      ldap_config :username_attribute, 'uid'
    end

    def ldap_can_search_anonymously?
      ldap_config :can_search_anonymously, true
    end
  end
end
