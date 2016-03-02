Embulk::JavaPlugin.register_filter(
  "encrypt", "org.embulk.filter.encrypt.EncryptFilterPlugin",
  File.expand_path('../../../../classpath', __FILE__))
