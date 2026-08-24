def task_funk
5.times do |i|
puts "task"
puts i
sleep 2
end
end

def task_funk2
5.times do |i|
puts "task"
puts i+1
sleep 2
end
end

# ここからがメイン

puts "start"

tsk = Task.new_task( :task_funk)
tsk2 = Task.new_task( :task_funk2)
puts tsk
puts tsk2
tsk.run
tsk2.run
sleep 10

puts "end"