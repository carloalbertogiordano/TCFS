#include "../../common.h"
#include "../print/print_utils.h"
#include "/usr/include/nlohmann/json.hpp" // Assuming you're using nlohmann's JSON library
#include <cstdlib>                        // For malloc and free
#include <cstring>                        // For strcpy
#include <iostream>
#include <string.h>
#include <vector>

/**
 * @file json_tools.cpp
 * @brief This file provides function to cast either qm_user, qm_shared or
 * qm_broad to a json string and vice versa
 * @note All the functions here are C++ functions, so we could use
 * nlohmann-json library
 * @note Learn more on [nlohmann-json](https://github.com/nlohmann/json)
 * */

/**
 * @brief Cast a qm_user, qm_shared or qm_broad struct to a json string
 * representing the struct
 * @param qmt       @see common.h
 * @param q_mess     The structure from which the json will be built
 * @return char* The json string
 * */
char *
struct_to_json (qm_type qmt, void *q_mess)
{
  nlohmann::json json_obj;

  switch (qmt)
    {
    case USER:
      {
        qm_user *user = static_cast<qm_user *> (q_mess);
        if (user->user_op == REGISTER)
          print_msg ("Register");
        if (user->user_op == UNREGISTER)
          print_msg ("Unregister");
        json_obj["user_op"] = user->user_op;
        json_obj["pid"] = user->pid;
        json_obj["user"] = user->user;
        json_obj["pubkey"] = user->pubkey;
        break;
      }
    case SHARED:
      {
        qm_shared *shared = static_cast<qm_shared *> (q_mess);
        json_obj["fd"] = shared->fd;

        // Converti la matrice di stringhe in un array di stringhe JSON
        nlohmann::json userlist_array = nlohmann::json::array ();
        for (size_t i = 0; shared->userlist[i] != nullptr; ++i)
          {
            userlist_array.push_back (shared->userlist[i]);
          }
        json_obj["userlist"] = userlist_array;

        json_obj["keypart"] = shared->keypart;
        break;
      }
    case BROADCAST:
      {
        qm_broad *broad = static_cast<qm_broad *> (q_mess);
        json_obj["data"] = broad->data;
        break;
      }
    }
  // Cast Json obj to string
  std::string json_str = json_obj.dump ();
  // Allocate memory for result
  char *result = (char *)malloc (json_str.size () + 1);
  if (result)
    {
      strcpy (result, json_str.c_str ());
    }
  print_msg ("JSONIFIED: %s", result);
  return result;
}

/**
 * @brief Cast a json string to a struct
 * @param json_string      The string containing the json that
 * represents the struct
 * @param type     Will be set to the type of the struct
 * @return void* This is the actual allocated structure, casted to void
 * @note To cast the returned param to the structure you probably need to use a
 * switch(type) and cast it to a struct
 * @see common.h
 * */
void *
string_to_struct (const char *json_string, qm_type *type)
{
  try
    {
      nlohmann::json json_obj = nlohmann::json::parse (json_string);

      if (json_obj.contains ("user_op"))
        {
          *type = USER;
          qm_user *user
              = static_cast<qm_user *> (std::malloc (sizeof (qm_user)));
          user->user_op = json_obj["user_op"];
          user->pid = json_obj["pid"];
          user->user = strdup (json_obj["user"].get<std::string> ().c_str ());
          user->pubkey
              = strdup (json_obj["pubkey"].get<std::string> ().c_str ());
          return user;
        }
      else if (json_obj.contains ("fd"))
        {
          *type = SHARED;
          qm_shared *shared
              = static_cast<qm_shared *> (std::malloc (sizeof (qm_shared)));
          shared->fd = json_obj["fd"];

          // Populate userlist array
          std::vector<std::string> userlist = json_obj["userlist"];
          shared->userlist = static_cast<char **> (
              std::malloc ((userlist.size () + 1) * sizeof (char *)));
          for (size_t i = 0; i < userlist.size (); ++i)
            {
              shared->userlist[i] = strdup (userlist[i].c_str ());
            }
          shared->userlist[userlist.size ()] = nullptr;

          shared->keypart
              = strdup (json_obj["keypart"].get<std::string> ().c_str ());
          return shared;
        }
      else if (json_obj.contains ("data"))
        {
          *type = BROADCAST;
          qm_broad *broad
              = static_cast<qm_broad *> (std::malloc (sizeof (qm_broad)));
          broad->data = strdup (json_obj["data"].get<std::string> ().c_str ());
          return broad;
        }
      else
        {
          *type = QM_TYPE_UNDEFINED;
          return nullptr;
        }
    }
  catch (const std::exception &e)
    {
      std::cerr << "Error parsing JSON: " << e.what () << std::endl;
      return nullptr;
    }
}
