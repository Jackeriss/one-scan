import os
import sys

from app.util.config_util import config


def get_plugins(plugin_type):
    plugins = {}
    plugin_path = os.path.join(config.base_dir, "plugin", plugin_type)
    file_list = os.listdir(plugin_path)
    if plugin_path not in sys.path:
        sys.path.insert(0, plugin_path)
    for file_name in file_list:
        if ".py" in file_name:
            if file_name == "__init__.py":
                continue
            if ".pyc" in file_name:
                continue
            module_name = f"app.plugin.{plugin_type}.{file_name[:-3]}"
            plugin = __import__(module_name, globals(), locals(), ["run", "__plugin__"])
            plugins[plugin.__plugin__] = plugin.run
    return plugins
