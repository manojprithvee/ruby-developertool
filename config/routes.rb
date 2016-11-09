Developertool::Application.routes.draw do
  get "count.html" => 'tools#word_count'
  get "diff.html" => 'tools#differ_text'
  get "password_gen.html" => 'tools#password_gen'
  get "hash.html" => 'tools#hash_generator'
  get "urlencode.html" => 'tools#url_encode'
  get "find.html" => 'tools#string_search'
  get "pretty.html" => 'tools#code_format'
  get "about.html" => "tools#about"
  get "contact.html" => "tools#contact"
  get "/" => "tools#index"
  get "index.html" => "tools#index"
  get "privacypolicy.html" => "tools#privacypolicy"
  get "base64encode.html" => "tools#base64encode"
  # The priority is based upon order of creation: first created -> highest priority.
  # See how all your routes lay out with "rake routes".

  # You can have the root of your site routed with "root"
  # root 'welcome#index'

  # Example of regular route:
  #   get 'products/:id' => 'catalog#view'

  # Example of named route that can be invoked with purchase_url(id: product.id)
  #   get 'products/:id/purchase' => 'catalog#purchase', as: :purchase

  # Example resource route (maps HTTP verbs to controller actions automatically):
  #   resources :products

  # Example resource route with options:
  #   resources :products do
  #     member do
  #       get 'short'
  #       post 'toggle'
  #     end
  #
  #     collection do
  #       get 'sold'
  #     end
  #   end

  # Example resource route with sub-resources:
  #   resources :products do
  #     resources :comments, :sales
  #     resource :seller
  #   end

  # Example resource route with more complex sub-resources:
  #   resources :products do
  #     resources :comments
  #     resources :sales do
  #       get 'recent', on: :collection
  #     end
  #   end
  
  # Example resource route with concerns:
  #   concern :toggleable do
  #     post 'toggle'
  #   end
  #   resources :posts, concerns: :toggleable
  #   resources :photos, concerns: :toggleable

  # Example resource route within a namespace:
  #   namespace :admin do
  #     # Directs /admin/products/* to Admin::ProductsController
  #     # (app/controllers/admin/products_controller.rb)
  #     resources :products
  #   end
end
