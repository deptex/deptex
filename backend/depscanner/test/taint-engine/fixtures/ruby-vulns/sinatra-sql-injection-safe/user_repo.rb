module UserRepo
  def self.find_by_name(name)
    # find_by uses bound parameters and is not in the sink list — engine
    # treats this as the safe shape vs. the vuln fixture's `where("...#{q}...")`.
    User.find_by(name: name)
  end
end
