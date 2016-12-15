class Webnotifer < ActiveRecord::Migration
  def self.up
      create_table :books do |t|
         t.column :url, :string, :limit => 254, :null => false
         t.column :email, :string, :limit => 254, :null => false
         t.column :key, :string, :limit => 32, null=> false
      end
   end
   
   def self.down
      drop_table :books
   end
end
